package memory_test

import (
	"context"
	"errors"
	"testing"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

func TestIntegrationStoreRejectsInvalidCapacity(t *testing.T) {
	if _, err := memory.NewIntegrationStore(0); !errors.Is(
		err, auth.ErrInvalidConfig,
	) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestIntegrationStoreDuplicatesAndCapacity(t *testing.T) {
	ctx := context.Background()

	store, err := memory.NewIntegrationStore(2)
	if err != nil {
		t.Fatal(err)
	}

	first := auth.Digest{1}
	second := auth.Digest{2}
	token := auth.IntegrationToken{ID: "a", TenantID: "t", Principal: "p"}

	if err := store.Issue(ctx, first, token); err != nil {
		t.Fatal(err)
	}

	if err := store.Issue(ctx, second, token); err == nil {
		t.Fatal("duplicate ID was accepted")
	}

	other := auth.IntegrationToken{ID: "b", TenantID: "t", Principal: "p"}
	if err := store.Issue(ctx, first, other); err == nil {
		t.Fatal("duplicate digest was accepted")
	}

	if err := store.Issue(ctx, second, other); err != nil {
		t.Fatal(err)
	}

	third := auth.IntegrationToken{ID: "c", TenantID: "t", Principal: "p"}
	if err := store.Issue(ctx, auth.Digest{3}, third); err == nil {
		t.Fatal("capacity was not enforced")
	}

	// Rotating onto a digest already in use must fail and keep both live.
	if _, err := store.Rotate(ctx, "a", second); err == nil {
		t.Fatal("rotation onto a taken digest was accepted")
	}

	if _, err := store.Lookup(ctx, first); err != nil {
		t.Fatalf("original digest lost after failed rotation: %v", err)
	}
}

func TestIntegrationStoreRevokeIsIdempotentAndFinal(t *testing.T) {
	ctx := context.Background()

	store, err := memory.NewIntegrationStore(1)
	if err != nil {
		t.Fatal(err)
	}

	digest := auth.Digest{1}
	token := auth.IntegrationToken{ID: "a", TenantID: "t", Principal: "p"}

	if err := store.Issue(ctx, digest, token); err != nil {
		t.Fatal(err)
	}

	for range 2 {
		if err := store.Revoke(ctx, "a"); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := store.Lookup(ctx, digest); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("revoked lookup: %v", err)
	}

	if _, err := store.Rotate(ctx, "a", auth.Digest{2}); !errors.Is(
		err, auth.ErrNotFound,
	) {
		t.Fatalf("revoked rotate: %v", err)
	}
}
