package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

func testManager(t *testing.T) (*auth.Manager, *time.Time) {
	t.Helper()

	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)

	store, err := memory.New(100)
	if err != nil {
		t.Fatal(err)
	}

	config := auth.DefaultConfig()
	config.TTL = time.Hour
	config.IdleTimeout = 10 * time.Minute
	config.Clock = func() time.Time { return now }

	manager, err := auth.New(store, config)
	if err != nil {
		t.Fatal(err)
	}

	return manager, &now
}

func issue(
	t *testing.T,
	manager *auth.Manager,
	subject string,
) auth.IssuedSession {
	t.Helper()

	issued, err := manager.Start(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}

	return issued
}

func TestSessionLifecycle(t *testing.T) {
	manager, now := testManager(t)
	ctx := context.Background()
	first := issue(t, manager, "alice")
	second := issue(t, manager, "alice")

	other := issue(t, manager, "bob")
	if first.Token == second.Token || first.Session.ID == second.Session.ID {
		t.Fatal("sessions must be independently random")
	}

	*now = now.Add(5 * time.Minute)

	session, err := manager.Authenticate(ctx, first.Token)
	if err != nil || session.SubjectID != "alice" ||
		!session.LastSeenAt.Equal(*now) {
		t.Fatalf("unexpected authentication: %+v, %v", session, err)
	}

	if err := manager.Revoke(ctx, first.Token); err != nil {
		t.Fatal(err)
	}

	if _, err := manager.Authenticate(
		ctx,
		first.Token,
	); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatalf("revoked session accepted: %v", err)
	}

	if err := manager.RevokeSubject(ctx, "alice"); err != nil {
		t.Fatal(err)
	}

	if _, err := manager.Authenticate(
		ctx,
		second.Token,
	); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatalf("subject revocation ignored: %v", err)
	}

	if _, err := manager.Authenticate(ctx, other.Token); err != nil {
		t.Fatalf("revocation crossed subjects: %v", err)
	}

	encoded, err := json.Marshal(first)
	if err != nil || strings.Contains(string(encoded), first.Token) {
		t.Fatal("issued session leaked its bearer token through JSON")
	}
}

func TestSessionDeadlines(t *testing.T) {
	t.Run("idle boundary", func(t *testing.T) {
		manager, now := testManager(t)
		issued := issue(t, manager, "alice")
		*now = now.Add(10 * time.Minute)

		if _, err := manager.Authenticate(
			context.Background(),
			issued.Token,
		); !errors.Is(
			err,
			auth.ErrUnauthenticated,
		) {
			t.Fatalf("idle deadline accepted: %v", err)
		}
	})

	t.Run("activity never extends absolute deadline", func(t *testing.T) {
		manager, now := testManager(t)
		issued := issue(t, manager, "alice")

		for i := 0; i < 11; i++ {
			*now = now.Add(5 * time.Minute)

			session, err := manager.Authenticate(
				context.Background(),
				issued.Token,
			)
			if err != nil ||
				!session.ExpiresAt.Equal(issued.Session.ExpiresAt) {
				t.Fatalf("activity changed absolute expiry: %v", err)
			}
		}

		*now = now.Add(5 * time.Minute)

		if _, err := manager.Authenticate(
			context.Background(),
			issued.Token,
		); !errors.Is(
			err,
			auth.ErrUnauthenticated,
		) {
			t.Fatalf("absolute deadline accepted: %v", err)
		}
	})
}

func TestRotationSingleUse(t *testing.T) {
	manager, now := testManager(t)
	issued := issue(t, manager, "alice")
	*now = now.Add(5 * time.Minute)
	ctx := context.Background()

	var (
		winners atomic.Int32
		group   sync.WaitGroup
	)
	for i := 0; i < 16; i++ {
		group.Go(func() {
			replacement, err := manager.Rotate(ctx, issued.Token)
			if err != nil {
				if !errors.Is(err, auth.ErrUnauthenticated) {
					t.Errorf("unexpected rotation error: %v", err)
				}

				return
			}

			winners.Add(1)

			if replacement.Token == issued.Token ||
				!replacement.Session.ExpiresAt.Equal(issued.Session.ExpiresAt) {
				t.Error("rotation reused token or extended absolute expiry")
			}

			if _, err := manager.Authenticate(
				ctx,
				replacement.Token,
			); err != nil {
				t.Errorf("replacement unusable: %v", err)
			}
		})
	}

	group.Wait()

	if winners.Load() != 1 {
		t.Fatalf("rotation winners = %d, want 1", winners.Load())
	}

	if _, err := manager.Authenticate(
		ctx,
		issued.Token,
	); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatalf("old token still works: %v", err)
	}
}

func TestCancellationAndValidation(t *testing.T) {
	manager, _ := testManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := manager.Start(
		ctx,
		"alice",
	); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatalf("canceled issuance: %v", err)
	}

	issued := issue(t, manager, "alice")
	if _, err := manager.Authenticate(
		ctx,
		issued.Token,
	); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatalf("canceled authentication: %v", err)
	}

	if _, err := manager.Start(
		context.Background(),
		"  ",
	); !errors.Is(
		err,
		auth.ErrInvalidSubject,
	) {
		t.Fatalf("empty subject accepted: %v", err)
	}

	for _, config := range []auth.Config{
		{},
		{TTL: time.Hour, IdleTimeout: -1, Clock: time.Now},
		{TTL: time.Hour, IdleTimeout: 2 * time.Hour, Clock: time.Now},
	} {
		store, _ := memory.New(1)
		if _, err := auth.New(store, config); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
}

type brokenStore struct {
	auth.SessionStore
	err error
}

func (s brokenStore) Use(
	context.Context, auth.Digest, time.Time, time.Duration,
) (auth.Session, error) {
	return auth.Session{ID: "injected", SubjectID: "admin"}, s.err
}

func TestStoreFailureDeniesAuthentication(t *testing.T) {
	manager, _ := testManager(t)
	issued := issue(t, manager, "alice")

	for _, failure := range []error{errors.New("database unavailable"), nil} {
		broken, err := auth.New(brokenStore{err: failure}, auth.DefaultConfig())
		if err != nil {
			t.Fatal(err)
		}

		if _, err := broken.Authenticate(
			context.Background(),
			issued.Token,
		); err == nil {
			t.Fatal("store failure or invalid record authenticated")
		}
	}
}

func FuzzTokenDigest(f *testing.F) {
	f.Add(strings.Repeat("A", 43))
	f.Add("")
	f.Add(strings.Repeat("_", 43))
	f.Fuzz(func(t *testing.T, token string) {
		first, err := auth.TokenDigest(token)
		if err == nil {
			second, err := auth.TokenDigest(token)
			if err != nil || first != second || len(token) != 43 {
				t.Fatal("token digest is not deterministic and bounded")
			}
		}
	})
}
