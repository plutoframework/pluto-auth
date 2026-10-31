package oidcpostgres_test

import (
	"context"
	"net/http"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/httpauth"
	"github.com/plutoframework/pluto-auth/methods/oidc"
	"github.com/plutoframework/pluto-auth/methods/oidc/oidchttp"
	"github.com/plutoframework/pluto-auth/stores/postgres"
	oidcpostgres "github.com/plutoframework/pluto-auth/stores/postgres/oidc"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ConfigureOIDC accepts real host integrations; it does not execute at package
// initialization. Apply explicit migrations before calling it at startup.
func ConfigureOIDC(
	ctx context.Context,
	pool *pgxpool.Pool,
	key []byte,
	provider oidc.Config,
	origins []string,
	ingress func(http.Handler) http.Handler,
) (http.Handler, error) {
	pending, err := oidcpostgres.New(pool, key, 10000)
	if err != nil {
		return nil, err
	}

	accounts, err := postgres.NewLocal(pool)
	if err != nil {
		return nil, err
	}

	sessions, err := auth.New(accounts, auth.DefaultConfig())
	if err != nil {
		return nil, err
	}

	provider.Transactions = pending

	client, err := oidc.New(ctx, provider)
	if err != nil {
		return nil, err
	}

	service, err := oidc.NewService(client, pending, sessions, false)
	if err != nil {
		return nil, err
	}

	return oidchttp.New(service, oidchttp.Config{
		Transport:       httpauth.Config{TrustedOrigins: origins},
		Ingress:         ingress,
		SuccessPath:     "/",
		CookieNamespace: provider.Issuer + ":" + provider.ClientID,
	})
}
