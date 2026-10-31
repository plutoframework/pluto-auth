// Package passwordhttp supplies thin POST-only local-credential handlers.
// Mount using http.StripPrefix if desired. Applications MUST supply trusted
// client ingress limiting in addition to the service's per-identifier limiter.
package passwordhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/httpauth"
	"github.com/plutoframework/pluto-auth/methods/password"
)

type Config struct {
	Transport httpauth.Config

	// Ingress must bound requests using a trusted client identity before decoding
	// or KDF work. Do not trust raw forwarding headers from arbitrary clients.
	Ingress func(http.Handler) http.Handler

	// OnError receives only public sentinel errors, never raw input or secrets.
	OnError func(context.Context, error)
}

type Handler struct {
	service   *password.Service
	transport *httpauth.Transport
	handler   http.Handler
	onError   func(context.Context, error)
}

func New(service *password.Service, config Config) (*Handler, error) {
	if service == nil || config.Ingress == nil {
		return nil, password.ErrInvalidConfig
	}

	transport, err := httpauth.New(service.Sessions(), config.Transport)
	if err != nil {
		return nil, err
	}

	h := &Handler{
		service:   service,
		transport: transport,
		onError:   config.OnError,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll", h.enroll)
	mux.HandleFunc("POST /verification", h.verification)
	mux.HandleFunc("POST /verify", h.verify)
	mux.HandleFunc("POST /recovery", h.recovery)
	mux.HandleFunc("POST /reset", h.reset)
	mux.HandleFunc("POST /signin", h.signin)
	mux.Handle("POST /logout", transport.Require(http.HandlerFunc(h.logout)))

	h.handler = config.Ingress(transport.Guard(mux))
	if h.handler == nil {
		return nil, password.ErrInvalidConfig
	}

	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.handler.ServeHTTP(w, r)
}

func (h *Handler) Transport() *httpauth.Transport { return h.transport }

type (
	emailInput struct {
		Email string `json:"email"`
	}
	passwordInput struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
)

type (
	tokenInput struct {
		Token string `json:"token"`
	}
	resetInput struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
)

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		write(w, http.StatusBadRequest, "invalid_request")

		return false
	}

	r.Body = http.MaxBytesReader(w, r.Body, 8192)

	body, err := io.ReadAll(r.Body)
	if err != nil || !utf8.Valid(body) || !uniqueObject(body) {
		write(w, http.StatusBadRequest, "invalid_request")

		return false
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		write(w, http.StatusBadRequest, "invalid_request")

		return false
	}

	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		write(w, http.StatusBadRequest, "invalid_request")

		return false
	}

	return true
}

// Reject duplicate (including case-variant) fields and non-object JSON before
// typed decoding; the 8 KiB bound also bounds the temporary key set.
func uniqueObject(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))

	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return false
	}

	seen := make(map[string]struct{})

	for decoder.More() {
		field, err := decoder.Token()
		if err != nil {
			return false
		}

		key, ok := field.(string)
		if !ok {
			return false
		}

		key = strings.ToLower(key)
		if _, exists := seen[key]; exists {
			return false
		}

		seen[key] = struct{}{}

		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return false
		}
	}

	if _, err := decoder.Token(); err != nil {
		return false
	}

	return decoder.Decode(new(any)) == io.EOF
}

func (h *Handler) enroll(w http.ResponseWriter, r *http.Request) {
	var input passwordInput
	if !decode(w, r, &input) {
		return
	}

	h.result(w, r, h.service.Enroll(r.Context(), input.Email,
		[]byte(input.Password)), http.StatusAccepted)
}

func (h *Handler) verification(w http.ResponseWriter, r *http.Request) {
	var input emailInput
	if !decode(w, r, &input) {
		return
	}

	h.result(w, r, h.service.RequestVerification(r.Context(), input.Email),
		http.StatusAccepted)
}

func (h *Handler) recovery(w http.ResponseWriter, r *http.Request) {
	var input emailInput
	if !decode(w, r, &input) {
		return
	}

	h.result(w, r, h.service.RequestRecovery(r.Context(), input.Email),
		http.StatusAccepted)
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	var input tokenInput
	if !decode(w, r, &input) {
		return
	}

	h.result(
		w,
		r,
		h.service.VerifyEmail(r.Context(), input.Token),
		http.StatusOK,
	)
}

func (h *Handler) reset(w http.ResponseWriter, r *http.Request) {
	var input resetInput
	if !decode(w, r, &input) {
		return
	}

	h.result(w, r, h.service.ResetPassword(r.Context(), input.Token,
		[]byte(input.Password)), http.StatusOK)
}

func (h *Handler) signin(w http.ResponseWriter, r *http.Request) {
	var input passwordInput
	if !decode(w, r, &input) {
		return
	}

	issued, err := h.service.SignIn(
		r.Context(),
		input.Email,
		[]byte(input.Password),
	)
	if err == nil {
		err = h.transport.WriteCookie(w, issued)
	}

	h.result(w, r, err, http.StatusOK)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	token, err := h.transport.Token(r)
	if err == nil {
		err = h.service.Sessions().Revoke(r.Context(), token)
	}

	if err == nil {
		h.transport.ClearCookie(w)
	}

	h.result(w, r, err, http.StatusOK)
}

func (h *Handler) result(w http.ResponseWriter, r *http.Request,
	err error, success int,
) {
	if err == nil {
		write(w, success, "accepted")

		return
	}

	status, code := http.StatusServiceUnavailable, "authentication_unavailable"
	public := password.ErrUnavailable

	switch {
	case errors.Is(err, password.ErrInvalidCredentials),
		errors.Is(err, auth.ErrAuthenticationRequired),
		errors.Is(err, auth.ErrUnauthenticated):
		status, code, public = http.StatusUnauthorized, "invalid_credentials",
			password.ErrInvalidCredentials
	case errors.Is(err, password.ErrInvalidChallenge):
		status, code, public = http.StatusBadRequest, "invalid_challenge",
			password.ErrInvalidChallenge
	case errors.Is(err, password.ErrInvalidEmail),
		errors.Is(err, password.ErrPasswordPolicy):
		status, code, public = http.StatusBadRequest, "invalid_request",
			password.ErrPasswordPolicy
	case errors.Is(err, password.ErrLimited):
		status, code, public = http.StatusTooManyRequests, "request_limited",
			password.ErrLimited
	}

	if h.onError != nil {
		h.onError(r.Context(), public)
	}

	write(w, status, code)
}

func write(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(struct {
		Code string `json:"code"`
	}{code})
}
