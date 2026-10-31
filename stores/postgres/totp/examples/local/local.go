// Package local demonstrates explicit password + native-factor construction.
// The host applies migrations and supplies real keys, limits and delivery.
package local

import (
	"context"
	"net/http"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/httpauth"
	"github.com/plutoframework/pluto-auth/methods/password"
	"github.com/plutoframework/pluto-auth/methods/totp"
	"github.com/plutoframework/pluto-auth/methods/totp/totphttp"
	"github.com/plutoframework/pluto-auth/stores/postgres"
	totppostgres "github.com/plutoframework/pluto-auth/stores/postgres/totp"
)

type Dependencies struct {
	Database  postgres.TransactionDB
	Protector totp.Protector
	Limiter   password.AttemptLimiter
	Sender    password.Sender
	Ingress   func(http.Handler) http.Handler
	Changed   func(context.Context, string, totp.Action)
	Origins   []string
	Issuer    string
}

// New returns both adapters so the host can mount MFA-aware /begin and /finish
// alongside password enrollment, verification and recovery routes. Use the
// returned factor transport for protected routes. There is no startup DDL.
func New(
	ctx context.Context,
	deps Dependencies,
) (*password.Service, *totphttp.Handler, error) {
	store, err := totppostgres.New(deps.Database)
	if err != nil {
		return nil, nil, err
	}

	hasher, err := password.NewHasher(password.DefaultConfig())
	if err != nil {
		return nil, nil, err
	}

	sessions := auth.DefaultConfig()

	primary, err := password.NewService(
		ctx,
		store,
		hasher,
		deps.Limiter,
		deps.Sender,
		sessions,
		password.DefaultLifecycleConfig(),
	)
	if err != nil {
		return nil, nil, err
	}

	factors, err := totp.New(
		store,
		deps.Protector,
		deps.Limiter,
		totp.Config{
			Issuer:   deps.Issuer,
			Sessions: sessions,
			Changed:  deps.Changed,
		},
	)
	if err != nil {
		return nil, nil, err
	}

	handler, err := totphttp.New(factors, totphttp.Config{
		Transport: httpauth.Config{TrustedOrigins: deps.Origins},
		Ingress:   deps.Ingress, Primary: primary.BeginSignIn,
	})
	if err != nil {
		return nil, nil, err
	}

	return primary, handler, nil
}
