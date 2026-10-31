// Package oidchttp adapts OIDC sign-in to browser cookies. Mount with StripPrefix.
package oidchttp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/plutoframework/pluto-auth/httpauth"
	"github.com/plutoframework/pluto-auth/methods/oidc"
)

type Config struct {
	Transport httpauth.Config
	Ingress   func(http.Handler) http.Handler

	// SuccessPath is a fixed local path, never supplied by the browser/provider.
	SuccessPath string

	// CookieNamespace must be stable and unique for each configured client.
	CookieNamespace string
}

type Handler struct {
	service   *oidc.Service
	transport *httpauth.Transport
	handler   http.Handler
	cookie    string
	success   string
}

func New(service *oidc.Service, config Config) (*Handler, error) {
	u, err := url.Parse(config.SuccessPath)
	if service == nil || config.Ingress == nil ||
		config.CookieNamespace == "" ||
		err != nil ||
		!strings.HasPrefix(config.SuccessPath, "/") ||
		strings.HasPrefix(config.SuccessPath, "//") ||
		strings.ContainsAny(config.SuccessPath, "\\\r\n") ||
		strings.HasPrefix(
			u.Path,
			"//",
		) || strings.ContainsAny(u.Path, "\\\r\n") ||
		u.Host != "" ||
		u.Scheme != "" ||
		u.RawQuery != "" ||
		u.Fragment != "" {
		return nil, oidc.ErrConfig
	}

	transport, err := httpauth.New(service.Sessions(), config.Transport)
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256([]byte(config.CookieNamespace))
	h := &Handler{
		service:   service,
		transport: transport,
		cookie: "__Host-pluto_oidc_" + hex.EncodeToString(
			digest[:8],
		),
		success: config.SuccessPath,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /begin", h.begin)
	mux.HandleFunc("GET /callback", h.callback)

	h.handler = config.Ingress(transport.Guard(mux))
	if h.handler == nil {
		return nil, oidc.ErrConfig
	}

	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	h.handler.ServeHTTP(w, r)
}

func deny(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	_ = json.NewEncoder(w).
		Encode(map[string]any{"error": map[string]string{"code": "authentication_failed"}})
}

func (h *Handler) begin(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength != 0 || r.URL.RawQuery != "" {
		deny(w)

		return
	}

	var bytes [32]byte

	_, _ = rand.Read(bytes[:])
	binding := base64.RawURLEncoding.EncodeToString(bytes[:])

	location, err := h.service.Begin(r.Context(), binding)
	if err != nil {
		deny(w)

		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.cookie,
		Value:    binding,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	if r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")

		_ = json.NewEncoder(w).
			Encode(map[string]any{"data": map[string]string{"authorization_url": location}})

		return
	}

	http.Redirect(w, r, location, http.StatusSeeOther)
}

func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.RawQuery) > 8192 {
		deny(w)

		return
	}

	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || query.Get("error") != "" ||
		(query.Get("iss") != "" && query.Get("iss") != h.service.Issuer()) {
		deny(w)

		return
	}

	for _, values := range query {
		if len(values) != 1 {
			deny(w)

			return
		}
	}

	var binding string

	count := 0

	for _, cookie := range r.Cookies() {
		if cookie.Name == h.cookie {
			binding = cookie.Value
			count++
		}
	}

	if count != 1 {
		deny(w)

		return
	}

	issued, err := h.service.SignIn(
		r.Context(),
		query.Get("state"),
		binding,
		query.Get("code"),
	)
	if err != nil {
		deny(w)

		return
	}

	if err := h.transport.WriteCookie(w, issued); err != nil {
		deny(w)

		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: h.cookie, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0),
	})
	http.Redirect(w, r, h.success, http.StatusSeeOther)
}
