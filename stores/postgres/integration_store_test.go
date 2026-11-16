package postgres

import (
	"context"
	"errors"
	"testing"

	auth "github.com/plutoframework/pluto-auth"
)

func TestMissingIntegrationTokenMapping(t *testing.T) {
	store, err := NewIntegrationStore(unavailableDB{})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if _, err := store.Lookup(ctx, auth.Digest{}); !errors.Is(
		err,
		auth.ErrNotFound,
	) {
		t.Fatalf("missing token not mapped: %v", err)
	}

	if _, err := store.Rotate(ctx, "id", auth.Digest{}); !errors.Is(
		err,
		auth.ErrNotFound,
	) {
		t.Fatalf("missing rotation not mapped: %v", err)
	}

	if err := store.Revoke(ctx, "id"); err == nil {
		t.Fatal("database revoke failure ignored")
	}

	if _, err := NewIntegrationStore(nil); err == nil {
		t.Fatal("nil database accepted")
	}
}
