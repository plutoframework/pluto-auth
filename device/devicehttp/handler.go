// Package devicehttp serves the device authorization grant over net/http.
//
// Public endpoints (code, token, revoke) are tenant-less and must sit behind
// ingress rate limiting. Owner endpoints (request, approve, deny, grants)
// require a verified browser session; unsafe methods additionally require a
// trusted Origin even for bearer credentials, so only a browser the owner is
// looking at can approve. Delegated tokens are refused there by the service.
package devicehttp

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/device"
	"github.com/plutoframework/pluto-auth/httpauth"
)

const maxBody = 16 << 10

// Config is explicit. Transport verifies owner sessions and trusted Origins.
type Config struct {
	Transport *httpauth.Transport

	// Ingress bounds clients, concurrency and queueing of the public routes.
	Ingress func(http.Handler) http.Handler
}

// Handler is mounted at a prefix with http.StripPrefix.
type Handler struct {
	service *device.Service
	mux     *http.ServeMux
}

func New(service *device.Service, config Config) (*Handler, error) {
	if service == nil || config.Transport == nil || config.Ingress == nil {
		return nil, auth.ErrInvalidConfig
	}

	handler := &Handler{service: service, mux: http.NewServeMux()}

	public := func(next http.HandlerFunc) http.Handler {
		return config.Ingress(next)
	}
	owner := func(next http.HandlerFunc) http.Handler {
		return config.Transport.RequireIdentity(next)
	}
	ownerWrite := func(next http.HandlerFunc) http.Handler {
		return config.Transport.Guard(config.Transport.RequireIdentity(next))
	}

	handler.mux.Handle("POST /code", public(handler.code))
	handler.mux.Handle("POST /token", public(handler.token))
	handler.mux.Handle("POST /revoke", public(handler.revoke))
	handler.mux.Handle("GET /request", owner(handler.request))
	handler.mux.Handle("POST /approve", ownerWrite(handler.approve))
	handler.mux.Handle("POST /deny", ownerWrite(handler.deny))
	handler.mux.Handle("GET /grants", owner(handler.grants))
	handler.mux.Handle("DELETE /grants/{id}", ownerWrite(handler.revokeGrant))

	return handler, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	h.mux.ServeHTTP(w, r)
}

type params map[string][]string

func (p params) get(name string) string {
	if values := p[name]; len(values) == 1 {
		return values[0]
	}

	return ""
}

func (p params) scopes() []string {
	return strings.Fields(p.get("scope"))
}

// parse reads a form or JSON body of string fields. Duplicate fields are
// rejected so a parameter can never be smuggled past validation.
func parse(w http.ResponseWriter, r *http.Request) (params, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	out := params{}

	switch media {
	case "application/x-www-form-urlencoded":
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, device.ErrInvalidRequest
		}

		values, err := url.ParseQuery(string(raw))
		if err != nil {
			return nil, device.ErrInvalidRequest
		}

		for name, list := range values {
			out[name] = list
		}
	case "application/json":
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		var body struct {
			GrantType    string   `json:"grant_type"`
			ClientID     string   `json:"client_id"`
			DeviceCode   string   `json:"device_code"`
			RefreshToken string   `json:"refresh_token"`
			Scope        string   `json:"scope"`
			Scopes       []string `json:"scopes"`
			Token        string   `json:"token"`
			UserCode     string   `json:"user_code"`
			Tenant       string   `json:"tenant"`
		}

		if err := decoder.Decode(&body); err != nil ||
			decoder.More() {
			return nil, device.ErrInvalidRequest
		}

		scope := body.Scope
		if len(body.Scopes) > 0 {
			scope = strings.Join(body.Scopes, " ")
		}

		for name, value := range map[string]string{
			"grant_type": body.GrantType, "client_id": body.ClientID,
			"device_code": body.DeviceCode, "refresh_token": body.RefreshToken,
			"scope": scope, "token": body.Token, "user_code": body.UserCode,
			"tenant": body.Tenant,
		} {
			if value != "" {
				out[name] = []string{value}
			}
		}
	default:
		return nil, device.ErrInvalidRequest
	}

	for _, list := range out {
		if len(list) > 1 {
			return nil, device.ErrInvalidRequest
		}
	}

	return out, nil
}

func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

// fail renders an RFC error. Unexpected errors are opaque.
func fail(w http.ResponseWriter, err error) {
	var protocol *device.Error
	if errors.As(err, &protocol) {
		if protocol.Code == device.ErrRateLimited.Code {
			w.Header().Set("Retry-After", "5")
		}

		write(w, protocol.Status, map[string]string{"error": protocol.Code})

		return
	}

	if errors.Is(err, auth.ErrUnauthenticated) {
		write(w, http.StatusUnauthorized,
			map[string]string{"error": "unauthenticated"})

		return
	}

	write(w, http.StatusServiceUnavailable,
		map[string]string{"error": "temporarily_unavailable"})
}

func (h *Handler) code(w http.ResponseWriter, r *http.Request) {
	in, err := parse(w, r)
	if err != nil {
		fail(w, err)

		return
	}

	code, err := h.service.Authorize(
		r.Context(),
		in.get("client_id"),
		in.scopes(),
	)
	if err != nil {
		fail(w, err)

		return
	}

	write(w, http.StatusOK, code)
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	in, err := parse(w, r)
	if err != nil {
		fail(w, err)

		return
	}

	response, err := h.service.Token(r.Context(), device.TokenRequest{
		GrantType:    in.get("grant_type"),
		ClientID:     in.get("client_id"),
		DeviceCode:   in.get("device_code"),
		RefreshToken: in.get("refresh_token"),
		Scopes:       in.scopes(),
	})
	if err != nil {
		fail(w, err)

		return
	}

	write(w, http.StatusOK, response)
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	in, err := parse(w, r)
	if err != nil {
		fail(w, err)

		return
	}

	if err := h.service.Revoke(r.Context(), in.get("token")); err != nil {
		fail(w, err)

		return
	}

	w.WriteHeader(http.StatusOK)
}

func identity(w http.ResponseWriter, r *http.Request) (*auth.Identity, bool) {
	value, ok := httpauth.IdentityFromContext(r.Context())
	if !ok {
		fail(w, auth.ErrUnauthenticated)
	}

	return value, ok
}

func (h *Handler) request(w http.ResponseWriter, r *http.Request) {
	who, ok := identity(w, r)
	if !ok {
		return
	}

	request, err := h.service.Lookup(
		r.Context(),
		who,
		r.URL.Query().Get("user_code"),
	)
	if err != nil {
		fail(w, err)

		return
	}

	write(w, http.StatusOK, map[string]any{
		"client_id":   request.ClientID,
		"client_name": request.ClientName,
		"actor_type":  request.ActorType,
		"scopes":      request.Scopes,
		"expires_in":  request.ExpiresIn,
	})
}

func (h *Handler) approve(w http.ResponseWriter, r *http.Request) {
	who, ok := identity(w, r)
	if !ok {
		return
	}

	in, err := parse(w, r)
	if err != nil {
		fail(w, err)

		return
	}

	err = h.service.Approve(
		r.Context(), who, in.get("user_code"), in.get("tenant"), in.scopes())
	if err != nil {
		fail(w, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) deny(w http.ResponseWriter, r *http.Request) {
	who, ok := identity(w, r)
	if !ok {
		return
	}

	in, err := parse(w, r)
	if err != nil {
		fail(w, err)

		return
	}

	if err := h.service.Deny(
		r.Context(),
		who,
		in.get("user_code"),
	); err != nil {
		fail(w, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) grants(w http.ResponseWriter, r *http.Request) {
	who, ok := identity(w, r)
	if !ok {
		return
	}

	grants, err := h.service.Grants(r.Context(), who)
	if err != nil {
		fail(w, err)

		return
	}

	type item struct {
		ID        string    `json:"id"`
		ClientID  string    `json:"client_id"`
		ActorType string    `json:"actor_type"`
		Tenant    string    `json:"tenant"`
		Scopes    []string  `json:"scopes"`
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
	}

	data := make([]item, 0, len(grants))
	for _, grant := range grants {
		data = append(data, item{
			grant.ID, grant.ClientID, grant.ActorType, grant.Tenant,
			grant.Scopes, grant.CreatedAt, grant.ExpiresAt,
		})
	}

	write(w, http.StatusOK, map[string]any{"data": data})
}

func (h *Handler) revokeGrant(w http.ResponseWriter, r *http.Request) {
	who, ok := identity(w, r)
	if !ok {
		return
	}

	if err := h.service.RevokeGrant(
		r.Context(),
		who,
		r.PathValue("id"),
	); err != nil {
		fail(w, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}
