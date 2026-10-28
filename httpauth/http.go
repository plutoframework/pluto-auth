// Package httpauth adapts Pluto sessions to net/http and Chi.
package httpauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.com/plutoframework/pluto-auth"
)

const CookieName = "__Host-pluto_session"

type sessionKey struct{}

type Config struct {
	// TrustedOrigins are exact browser origins, never wildcard patterns.
	// Explicit HTTP loopback origins support local development only. Session
	// cookies remain Secure, so use local HTTPS for browser authentication.
	TrustedOrigins []string
	// WriteError may supply the application's JSON envelope. It must not
	// expose credentials or internal storage errors to the client.
	WriteError func(http.ResponseWriter, *http.Request, int, string)
}

type Transport struct {
	manager    *auth.Manager
	origins    map[string]struct{}
	writeError func(http.ResponseWriter, *http.Request, int, string)
}

func New(manager *auth.Manager, config Config) (*Transport, error) {
	if manager == nil || len(config.TrustedOrigins) == 0 {
		return nil, auth.ErrInvalidConfig
	}

	transport := &Transport{
		manager:    manager,
		origins:    make(map[string]struct{}),
		writeError: config.WriteError,
	}

	if transport.writeError == nil {
		transport.writeError = defaultError
	}

	for _, origin := range config.TrustedOrigins {
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Host == "" || parsed.User != nil ||
			parsed.Path != "" || parsed.RawQuery != "" ||
			parsed.Fragment != "" || strings.Contains(origin, "*") ||
			origin != parsed.Scheme+"://"+parsed.Host {
			return nil, auth.ErrInvalidConfig
		}

		loopback := parsed.Hostname() == "localhost" ||
			parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1"
		if parsed.Scheme != "https" &&
			(parsed.Scheme != "http" || !loopback) {
			return nil, auth.ErrInvalidConfig
		}

		transport.origins[origin] = struct{}{}
	}

	return transport, nil
}

// Guard enforces exact Origin validation for unsafe browser methods. Missing,
// multiple and untrusted origins fail closed. Apply it to login and other
// unauthenticated state-changing authentication routes, too. It does not set
// CORS headers: configure credentialed CORS explicitly in the application.
func (t *Transport) Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			origins := r.Header.Values("Origin")
			if len(origins) != 1 {
				t.writeError(w, r, http.StatusForbidden, "untrusted_origin")

				return
			}

			if _, trusted := t.origins[origins[0]]; !trusted {
				t.writeError(w, r, http.StatusForbidden, "untrusted_origin")

				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// Require authenticates cookies and installs a session in the request context.
// Authentication never grants roles, permissions, or tenant membership.
func (t *Transport) Require(next http.Handler) http.Handler {
	return t.Guard(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var token string

			count := 0

			for _, cookie := range r.Cookies() {
				if cookie.Name == CookieName {
					token = cookie.Value
					count++
				}
			}

			if count != 1 {
				t.writeError(w, r, http.StatusUnauthorized, "unauthenticated")

				return
			}

			session, err := t.manager.Authenticate(r.Context(), token)
			if err != nil {
				status := http.StatusServiceUnavailable
				code := "authentication_unavailable"

				if errors.Is(err, auth.ErrUnauthenticated) {
					status = http.StatusUnauthorized
					code = "unauthenticated"
				}

				t.writeError(w, r, status, code)

				return
			}

			ctx := context.WithValue(r.Context(), sessionKey{}, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		}),
	)
}

func FromContext(ctx context.Context) (auth.Session, bool) {
	session, ok := ctx.Value(sessionKey{}).(auth.Session)

	return session, ok
}

func (t *Transport) WriteCookie(
	w http.ResponseWriter,
	issued auth.IssuedSession,
) error {
	if _, err := auth.TokenDigest(issued.Token); err != nil {
		return err
	}

	w.Header().Set("Cache-Control", "no-store")
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    issued.Token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  issued.Session.ExpiresAt,
	})

	return nil
}

// ClearCookie only removes the browser cookie. Revoke the stored session first.
func (t *Transport) ClearCookie(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
}

func defaultError(
	w http.ResponseWriter,
	_ *http.Request,
	status int,
	code string,
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code},
	})
}
