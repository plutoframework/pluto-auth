package httpauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	auth "github.com/plutoframework/pluto-auth"
)

type serviceKey struct{}

// ServiceFromContext returns the service identity installed by RequireService.
// It never returns a user session, and FromContext never returns a service
// identity: a handler must choose which kind of caller it accepts.
func ServiceFromContext(ctx context.Context) (auth.ServiceIdentity, bool) {
	if ctx == nil {
		return auth.ServiceIdentity{}, false
	}

	identity, ok := ctx.Value(serviceKey{}).(auth.ServiceIdentity)

	return identity, ok
}

// RequireService authenticates an integration token presented as
// "Authorization: Bearer <token>" and installs a service identity in the
// request context. It accepts no cookie, so requests carrying a session
// cookie fail, as do duplicate or malformed Authorization headers. A session
// token is not an integration token and fails here. The token is looked up on
// every request, so revocation and rotation apply to the next request. It
// performs no permission check: authorize through the application's policy.
// Without Config.Integrations every request fails closed.
func (t *Transport) RequireService(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		secret, ok := t.serviceCredential(r)
		if !ok || t.services == nil {
			t.writeError(w, r, http.StatusUnauthorized, "unauthenticated")

			return
		}

		identity, err := t.services.Authenticate(r.Context(), secret)
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

		ctx := context.WithValue(r.Context(), serviceKey{}, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (t *Transport) serviceCredential(r *http.Request) (string, bool) {
	for _, cookie := range r.Cookies() {
		if cookie.Name == CookieName {
			return "", false
		}
	}

	headers := r.Header.Values("Authorization")
	if len(headers) != 1 {
		return "", false
	}

	scheme, token, found := strings.Cut(headers[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" ||
		strings.TrimSpace(token) != token {
		return "", false
	}

	return token, true
}
