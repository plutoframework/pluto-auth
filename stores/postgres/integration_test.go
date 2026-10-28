package postgres_test

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/postgres"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv("PLUTO_AUTH_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip(
			"set PLUTO_AUTH_TEST_DATABASE_URL to a disposable PostgreSQL database",
		)
	}

	ctx := context.Background()

	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(admin.Close)

	schema := "auth_test_" + rand.Text()

	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if _, err := admin.Exec(
			ctx,
			"DROP SCHEMA "+quoted+" CASCADE",
		); err != nil {
			t.Errorf("clean up test schema: %v", err)
		}
	})

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}

	config.ConnConfig.RuntimeParams["search_path"] = quoted

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(pool.Close)

	if _, err := pool.Exec(ctx, postgres.Schema); err != nil {
		t.Fatal(err)
	}

	return pool
}

func TestPostgresLifecycle(t *testing.T) {
	pool := testPool(t)

	store, err := postgres.New(pool)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	config := auth.DefaultConfig()
	config.TTL = time.Hour
	config.IdleTimeout = 10 * time.Minute
	config.Clock = func() time.Time { return now }

	manager, err := auth.New(store, config)
	if err != nil {
		t.Fatal(err)
	}

	issued, err := manager.Start(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}

	var digest []byte

	err = pool.QueryRow(ctx,
		"SELECT token_digest FROM pluto_auth_sessions WHERE id = $1",
		issued.Session.ID).Scan(&digest)

	expected, digestErr := auth.TokenDigest(issued.Token)
	if err != nil || digestErr != nil || string(digest) != string(expected[:]) {
		t.Fatal("database did not store the expected token digest")
	}

	now = now.Add(5 * time.Minute)

	if _, err := manager.Authenticate(ctx, issued.Token); err != nil {
		t.Fatal(err)
	}

	// Real concurrent connections must agree on one rotation winner.
	var (
		winners atomic.Int32
		group   sync.WaitGroup
	)
	for i := 0; i < 8; i++ {
		group.Go(func() {
			rotated, err := manager.Rotate(ctx, issued.Token)
			if err != nil {
				if !errors.Is(err, auth.ErrUnauthenticated) {
					t.Errorf("rotation failed: %v", err)
				}

				return
			}

			winners.Add(1)

			if !rotated.Session.ExpiresAt.Equal(issued.Session.ExpiresAt) {
				t.Error("rotation extended expiry")
			}
		})
	}

	group.Wait()

	if winners.Load() != 1 {
		t.Fatalf("rotation winners = %d", winners.Load())
	}

	if err := manager.RevokeSubject(ctx, "alice"); err != nil {
		t.Fatal(err)
	}

	var count int

	err = pool.QueryRow(ctx,
		"SELECT count(*) FROM pluto_auth_sessions WHERE subject_id = $1",
		"alice").Scan(&count)
	if err != nil || count != 0 {
		t.Fatal("subject revocation left sessions behind")
	}

	issued, err = manager.Start(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(10 * time.Minute)

	if _, err := manager.Authenticate(
		ctx,
		issued.Token,
	); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatalf("idle boundary accepted: %v", err)
	}

	now = now.Add(time.Hour)

	removed, err := store.PruneExpired(ctx, now)
	if err != nil || removed != 1 {
		t.Fatalf("expiry cleanup removed=%d, err=%v", removed, err)
	}
}
