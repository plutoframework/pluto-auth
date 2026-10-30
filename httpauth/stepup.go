package httpauth

import (
	"errors"
	"net/http"

	auth "github.com/plutoframework/pluto-auth"
)

// RequireAuthentication authenticates normally, then checks server-owned method
// evidence. It performs no credential ceremony and never redirects automatically.
// The application presents its configured reauthentication flow on a 403 result.
func (t *Transport) RequireAuthentication(
	requirement auth.Requirement,
	next http.Handler,
) (http.Handler, error) {
	if requirement.Validate() != nil || next == nil {
		return nil, auth.ErrInvalidConfig
	}

	return t.Require(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := FromContext(r.Context())
			if !ok {
				t.writeError(w, r, http.StatusUnauthorized, "unauthenticated")

				return
			}

			if err := t.manager.CheckAuthentication(
				session,
				requirement,
			); err != nil {
				status := http.StatusForbidden
				code := "authentication_required"

				if errors.Is(err, auth.ErrUnauthenticated) {
					status = http.StatusUnauthorized
					code = "unauthenticated"
				}

				t.writeError(w, r, status, code)

				return
			}

			next.ServeHTTP(w, r)
		}),
	), nil
}
