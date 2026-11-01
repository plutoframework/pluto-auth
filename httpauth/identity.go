package httpauth

import (
	"context"
	"errors"
	"net/http"

	auth "github.com/plutoframework/pluto-auth"
)

type identityKey struct{}

// IdentityFromContext retrieves the opaque identity installed by RequireIdentity.
// A present identity still requires live validation by its configured issuer at
// each operation/use. It proves neither tenant membership nor resource access.
func IdentityFromContext(ctx context.Context) (*auth.Identity, bool) {
	if ctx == nil {
		return nil, false
	}

	identity, ok := ctx.Value(identityKey{}).(*auth.Identity)

	return identity, ok && identity != nil
}

// RequireIdentity preserves Require's credential ambiguity, bearer opt-in and
// cookie Origin rules, then supplies a callback-lifetime session identity. It is
// additive: existing FromContext consumers remain compatible.
func (t *Transport) RequireIdentity(next http.Handler) http.Handler {
	return t.Require(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := t.Token(r)
			if err == nil {
				err = t.manager.WithIdentity(
					r.Context(),
					token,
					func(ctx context.Context, identity *auth.Identity) error {
						ctx = context.WithValue(ctx, identityKey{}, identity)
						next.ServeHTTP(w, r.WithContext(ctx))

						return nil
					},
				)
			}

			if err != nil {
				status := http.StatusServiceUnavailable
				code := "authentication_unavailable"

				if errors.Is(err, auth.ErrUnauthenticated) {
					status = http.StatusUnauthorized
					code = "unauthenticated"
				}

				t.writeError(w, r, status, code)
			}
		}),
	)
}
