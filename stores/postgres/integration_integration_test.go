package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/postgres"
)

func integrationFixture(
	t *testing.T,
) (*auth.Integrations, *postgres.IntegrationStore, func(string) []byte) {
	t.Helper()

	pool := testPool(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, postgres.IntegrationSchema); err != nil {
		t.Fatal(err)
	}

	store, err := postgres.NewIntegrationStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	integrations, err := auth.NewIntegrations(store, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	stored := func(id string) []byte {
		var digest []byte

		err := pool.QueryRow(
			ctx,
			`SELECT token_digest FROM pluto_auth_integration_tokens WHERE id=$1`,
			id,
		).Scan(&digest)
		if err != nil {
			t.Fatal(err)
		}

		return digest
	}

	return integrations, store, stored
}

func TestIntegrationIssueLookupRotateRevoke(t *testing.T) {
	integrations, _, stored := integrationFixture(t)
	ctx := context.Background()

	issued, err := integrations.Issue(ctx, "tenant-1", "billing-worker")
	if err != nil {
		t.Fatal(err)
	}

	digest, err := auth.TokenDigest(issued.Secret)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(stored(issued.Token.ID), digest[:]) ||
		bytes.Contains(stored(issued.Token.ID), []byte(issued.Secret)) {
		t.Fatal("only the digest may be persisted")
	}

	identity, err := integrations.Authenticate(ctx, issued.Secret)
	if err != nil || identity.TenantID != "tenant-1" ||
		identity.Principal != "billing-worker" ||
		identity.TokenID != issued.Token.ID {
		t.Fatalf("lookup failed: %+v %v", identity, err)
	}

	rotated, err := integrations.Rotate(ctx, issued.Token.ID)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := integrations.Authenticate(
		ctx,
		issued.Secret,
	); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatalf("old secret survived rotation: %v", err)
	}

	if _, err := integrations.Authenticate(ctx, rotated.Secret); err != nil {
		t.Fatalf("new secret rejected: %v", err)
	}

	newDigest, _ := auth.TokenDigest(rotated.Secret)
	if !bytes.Equal(stored(issued.Token.ID), newDigest[:]) {
		t.Fatal("rotation did not replace the stored digest")
	}

	for range 2 {
		if err := integrations.Revoke(ctx, issued.Token.ID); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := integrations.Authenticate(
		ctx,
		rotated.Secret,
	); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatalf("revoked token authenticated: %v", err)
	}

	if _, err := integrations.Rotate(
		ctx,
		issued.Token.ID,
	); !errors.Is(
		err,
		auth.ErrNotFound,
	) {
		t.Fatalf("revoked token rotated: %v", err)
	}

	if _, err := integrations.Rotate(
		ctx,
		"missing",
	); !errors.Is(
		err,
		auth.ErrNotFound,
	) {
		t.Fatalf("unknown token rotated: %v", err)
	}

	if err := integrations.Revoke(ctx, "missing"); err != nil {
		t.Fatalf("revoking an unknown token must be idempotent: %v", err)
	}
}

func TestIntegrationStoreRejectsDuplicatesAndBadRows(t *testing.T) {
	_, store, _ := integrationFixture(t)
	ctx := context.Background()
	token := auth.IntegrationToken{
		ID: "one", TenantID: "t", Principal: "p", CreatedAt: time.Now(),
	}

	if err := store.Issue(ctx, auth.Digest{1}, token); err != nil {
		t.Fatal(err)
	}

	if err := store.Issue(ctx, auth.Digest{2}, token); err == nil {
		t.Fatal("duplicate id accepted")
	}

	token.ID = "two"
	if err := store.Issue(ctx, auth.Digest{1}, token); err == nil {
		t.Fatal("duplicate digest accepted")
	}

	token.TenantID = ""
	if err := store.Issue(ctx, auth.Digest{3}, token); err == nil {
		t.Fatal("empty tenant accepted by schema")
	}
}

func TestIntegrationConcurrentRotationLeavesOneLiveSecret(t *testing.T) {
	integrations, _, _ := integrationFixture(t)
	ctx := context.Background()

	issued, err := integrations.Issue(ctx, "tenant", "worker")
	if err != nil {
		t.Fatal(err)
	}

	const workers = 8

	secrets := make([]string, workers)

	var group sync.WaitGroup

	for i := range workers {
		group.Add(1)

		go func() {
			defer group.Done()

			rotated, err := integrations.Rotate(ctx, issued.Token.ID)
			if err != nil {
				t.Error(err)

				return
			}

			secrets[i] = rotated.Secret
		}()
	}

	group.Wait()

	live := 0

	for _, secret := range append(secrets, issued.Secret) {
		if _, err := integrations.Authenticate(ctx, secret); err == nil {
			live++
		}
	}

	if live != 1 {
		t.Fatalf("%d live secrets after concurrent rotation", live)
	}
}
