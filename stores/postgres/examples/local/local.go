// Package local shows explicit construction with application-owned delivery and
// limits. It does not bootstrap demo credentials, listen or send any messages.
package local

import (
	"context"
	"net/http"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/httpauth"
	"github.com/plutoframework/pluto-auth/methods/password"
	"github.com/plutoframework/pluto-auth/methods/password/passwordhttp"
	"github.com/plutoframework/pluto-auth/stores/postgres"

	"github.com/jackc/pgx/v5/pgxpool"
)

// New assumes Schema, LocalSchema and AuthenticationSchema were migrated. Production
// callers supply shared account limits, trusted-client ingress limits, a real
// sender with fixed HTTPS link destinations, and optionally a local blocklist.
func New(
	ctx context.Context,
	pool *pgxpool.Pool,
	sender password.Sender,
	limiter password.AttemptLimiter,
	ingress func(http.Handler) http.Handler,
	trustedOrigins []string,
	policy password.PasswordPolicy,
) (*password.Service, *passwordhttp.Handler, error) {
	store, err := postgres.NewLocal(pool)
	if err != nil {
		return nil, nil, err
	}

	hasher, err := password.NewHasher(password.DefaultConfig())
	if err != nil {
		return nil, nil, err
	}

	config := password.DefaultLifecycleConfig()
	config.Policy = policy

	service, err := password.NewService(
		ctx,
		store,
		hasher,
		limiter,
		sender,
		auth.DefaultConfig(),
		config,
	)
	if err != nil {
		return nil, nil, err
	}

	handler, err := passwordhttp.New(service, passwordhttp.Config{
		Transport: httpauth.Config{
			TrustedOrigins: trustedOrigins,
		},
		Ingress: ingress,
	})
	if err != nil {
		return nil, nil, err
	}

	return service, handler, nil
}
