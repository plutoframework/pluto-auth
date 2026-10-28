package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type unavailableDB struct{}

func (unavailableDB) Exec(
	context.Context, string, ...any,
) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("database unavailable")
}

func (unavailableDB) Query(
	context.Context, string, ...any,
) (pgx.Rows, error) {
	return nil, errors.New("database unavailable")
}

func (unavailableDB) QueryRow(context.Context, string, ...any) pgx.Row {
	return missingRow{}
}

type missingRow struct{}

func (missingRow) Scan(...any) error {
	return pgx.ErrNoRows
}

func TestMissingSessionMapping(t *testing.T) {
	store, err := New(unavailableDB{})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if _, err := store.Use(
		ctx,
		auth.Digest{},
		time.Now(),
		time.Minute,
	); !errors.Is(
		err,
		auth.ErrNotFound,
	) {
		t.Fatalf("missing session error not mapped: %v", err)
	}

	if _, err := store.Consume(
		ctx,
		auth.Digest{},
		time.Now(),
		time.Minute,
	); !errors.Is(
		err,
		auth.ErrNotFound,
	) {
		t.Fatalf("missing rotation error not mapped: %v", err)
	}

	if err := store.Delete(ctx, auth.Digest{}); err == nil {
		t.Fatal("database deletion failure ignored")
	}

	if err := store.DeleteSubject(ctx, "alice"); err == nil {
		t.Fatal("database subject deletion failure ignored")
	}
}

func TestPositiveIdleTimeoutNeverDisablesExpiry(t *testing.T) {
	for _, timeout := range []time.Duration{1, 999, 1000, 1001} {
		if idleMicroseconds(timeout) <= 0 {
			t.Fatal("positive duration disabled idle expiry")
		}
	}

	if idleMicroseconds(0) != 0 {
		t.Fatal("explicitly disabled timeout changed")
	}
}
