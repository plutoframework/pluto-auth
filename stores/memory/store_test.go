package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

func TestStorageContract(t *testing.T) {
	store, err := memory.New(1)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	session := auth.Session{
		ID: "one", SubjectID: "alice", CreatedAt: now,
		LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
	}
	ctx := context.Background()

	digest := auth.Digest{1}
	if err := store.Create(ctx, digest, session); err != nil {
		t.Fatal(err)
	}

	if err := store.Create(ctx, digest, session); err == nil {
		t.Fatal("duplicate digest accepted")
	}

	if err := store.Create(ctx, auth.Digest{2}, session); err == nil {
		t.Fatal("capacity not enforced")
	}

	used, err := store.Use(ctx, digest, now.Add(time.Minute), 0)
	if err != nil {
		t.Fatal(err)
	}

	backwards, err := store.Use(ctx, digest, now, 0)
	if err != nil || !backwards.LastSeenAt.Equal(used.LastSeenAt) {
		t.Fatal("activity moved backwards")
	}

	if _, err := store.Use(
		ctx,
		digest,
		now.Add(time.Hour),
		0,
	); !errors.Is(
		err,
		auth.ErrNotFound,
	) {
		t.Fatal("expiry boundary accepted")
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()

	if err := store.Delete(
		canceled,
		digest,
	); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatal("canceled deletion succeeded")
	}

	if _, err := store.Use(ctx, digest, now, 0); err != nil {
		t.Fatal("canceled deletion changed store")
	}

	if _, err := store.Consume(ctx, digest, now, 0); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Consume(
		ctx,
		digest,
		now,
		0,
	); !errors.Is(
		err,
		auth.ErrNotFound,
	) {
		t.Fatal("consumed session reused")
	}

	if _, err := store.Use(
		ctx,
		digest,
		now,
		0,
	); !errors.Is(
		err,
		auth.ErrNotFound,
	) {
		t.Fatal("session resurrected")
	}
}
