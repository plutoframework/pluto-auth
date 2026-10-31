// Package totphttp supplies Origin-checked native-factor JSON handlers.
package totphttp

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
	"github.com/plutoframework/pluto-auth/methods/totp"
)

const BrowserCookie = "__Host-pluto_factor"

type Config struct {
	Transport httpauth.Config
	Ingress   func(http.Handler) http.Handler

	// Primary must verify actual credentials and return a server-local ceremony.
	// password.Service.BeginSignIn is directly assignable. Never decode evidence.
	Primary func(context.Context, string, []byte) (auth.Ceremony, error)
}
type Handler struct {
	service   *totp.Service
	transport *httpauth.Transport
	primary   func(context.Context, string, []byte) (auth.Ceremony, error)
	handler   http.Handler
}

func New(service *totp.Service, config Config) (*Handler, error) {
	if service == nil || config.Ingress == nil || config.Primary == nil {
		return nil, totp.ErrConfig
	}

	transport, err := httpauth.New(service.Sessions(), config.Transport)
	if err != nil {
		return nil, err
	}

	h := &Handler{
		service:   service,
		transport: transport,
		primary:   config.Primary,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /begin", h.begin)
	mux.HandleFunc("POST /finish", h.finish)

	h.handler = config.Ingress(transport.Guard(mux))
	if h.handler == nil {
		return nil, totp.ErrConfig
	}

	return h, nil
}

func (h *Handler) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) {
	h.handler.ServeHTTP(w, r)
}

func (h *Handler) Transport() *httpauth.Transport { return h.transport }

type beginInput struct {
	Email    string      `json:"email"`
	Password string      `json:"password"`
	Action   totp.Action `json:"action"`
}
type finishInput struct {
	Challenge    string `json:"challenge"`
	Code         string `json:"code"`
	Recovery     bool   `json:"recovery"`
	Confirmation string `json:"confirmation"`
}

func (h *Handler) begin(w http.ResponseWriter, r *http.Request) {
	var input beginInput
	if !decode(w, r, &input) {
		return
	}

	ceremony, err := h.primary(r.Context(), input.Email, []byte(input.Password))
	if err != nil {
		failure(w, totp.ErrDenied)

		return
	}

	if input.Action == totp.SignIn && ceremony.Stage() == auth.Authenticated {
		_, at, _ := ceremony.PrimaryEvidence()

		// The manager checks the deadline against its configured clock; persistence
		// independently rechecks it after account lock waits.
		proof, err := ceremony.Complete(at)
		if err != nil {
			failure(w, totp.ErrDenied)

			return
		}

		issued, err := h.service.Sessions().
			StartAuthenticated(r.Context(), proof)
		if err != nil {
			failure(w, totp.ErrDenied)

			return
		}

		if err := h.transport.WriteCookie(w, issued); err != nil {
			failure(w, totp.ErrUnavailable)

			return
		}

		respond(w, struct {
			Authenticated bool `json:"authenticated"`
		}{true})

		return
	}

	browser := totp.Browser()

	// The display label is server-owned subject identity, never a client-selected
	// authority or supplied email that could disagree with the verified account.
	setup, err := h.service.Begin(
		r.Context(),
		ceremony,
		browser,
		input.Action,
		ceremony.Account().SubjectID,
	)
	if err != nil {
		failure(w, err)

		return
	}

	http.SetCookie(
		w,
		&http.Cookie{
			Name:     BrowserCookie,
			Value:    browser,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   300,
			Expires:  setup.Expires,
		},
	)
	respond(w, setup)
}

func (h *Handler) finish(w http.ResponseWriter, r *http.Request) {
	var input finishInput
	if !decode(w, r, &input) {
		return
	}

	var browser string

	found := false

	for _, cookie := range r.Cookies() {
		if cookie.Name == BrowserCookie {
			if found {
				failure(w, totp.ErrDenied)

				return
			}

			found = true
			browser = cookie.Value
		}
	}

	result, err := h.service.Finish(
		r.Context(),
		input.Challenge,
		browser,
		input.Code,
		input.Recovery,
		input.Confirmation,
	)
	if err != nil {
		failure(w, err)

		return
	}

	http.SetCookie(
		w,
		&http.Cookie{
			Name:     BrowserCookie,
			Value:    "",
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		},
	)

	if result.Issued.Token != "" {
		if err := h.transport.WriteCookie(w, result.Issued); err != nil {
			failure(w, totp.ErrUnavailable)

			return
		}
	}

	// Management results contain the new codes exactly once, never session tokens.
	respond(w, struct {
		RecoveryCodes []string `json:"recovery_codes,omitempty"`
	}{result.RecoveryCodes})
}

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		failure(w, totp.ErrDenied)

		return false
	}

	r.Body = http.MaxBytesReader(w, r.Body, 8192)

	body, err := io.ReadAll(r.Body)
	if err != nil || !utf8.Valid(body) || !uniqueObject(body) {
		failure(w, totp.ErrDenied)

		return false
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	if decoder.Decode(target) != nil ||
		!errors.Is(decoder.Decode(new(any)), io.EOF) {
		failure(w, totp.ErrDenied)

		return false
	}

	return true
}

// uniqueObject rejects duplicate (including case-variant) keys before decoding
// into typed request values. The body limit bounds its temporary key set.
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
		if decoder.Decode(&value) != nil {
			return false
		}
	}

	if _, err := decoder.Token(); err != nil {
		return false
	}

	return errors.Is(decoder.Decode(new(any)), io.EOF)
}

func respond(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	_ = json.NewEncoder(w).Encode(value)
}

func failure(w http.ResponseWriter, err error) {
	status := http.StatusUnauthorized

	code := "invalid_proof"
	if errors.Is(err, totp.ErrLimited) {
		status, code = http.StatusTooManyRequests, "request_limited"
	}

	if errors.Is(err, totp.ErrUnavailable) {
		status, code = http.StatusServiceUnavailable, "authentication_unavailable"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{code})
}
