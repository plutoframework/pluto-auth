package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/postgres"
)

func TestAuthenticationMigrationPreservesUnknownLegacyEvidence(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, postgres.LocalSchema); err != nil {
		t.Fatal(err)
	}

	_, err := pool.Exec(ctx, `INSERT INTO pluto_auth_accounts
        (id, email, password_hash, verified) VALUES ('legacy', 'legacy@example.test', 'test-only', true)`)
	if err != nil {
		t.Fatal(err)
	}

	plain, err := postgres.New(pool)
	if err != nil {
		t.Fatal(err)
	}

	legacyManager, err := auth.New(plain, auth.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Reproduce the pre-upgrade table shape using trusted test setup.
	issued, err := legacyManager.Start(ctx, "legacy")
	if err != nil {
		t.Fatal(err)
	}

	digest, err := auth.TokenDigest(issued.Token)
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.Exec(ctx, `INSERT INTO pluto_auth_local_sessions
        (token_digest, account_id, credential_version) VALUES ($1, 'legacy', 1)`, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(
		ctx,
		postgres.AuthenticationSchema+"\n"+postgres.ExternalSchema,
	); err != nil {
		t.Fatal(err)
	}

	store, err := postgres.NewLocal(pool)
	if err != nil {
		t.Fatal(err)
	}

	manager, err := auth.New(store, auth.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	session, err := manager.Authenticate(ctx, issued.Token)
	if err != nil || !session.Authentication.IsZero() {
		t.Fatal("migration changed legacy authentication evidence", err)
	}

	if err := manager.CheckAuthentication(
		session,
		auth.Requirement{MaxAge: time.Hour},
	); !errors.Is(
		err,
		auth.ErrAuthenticationRequired,
	) {
		t.Fatal("migration manufactured fresh authentication")
	}

	rotated, err := manager.Rotate(ctx, issued.Token)
	if err != nil || !rotated.Session.Authentication.IsZero() {
		t.Fatal("legacy rotation manufactured evidence", err)
	}
}
