package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
)

func TestIdentityProvenanceAndLifetime(t *testing.T) {
	manager, now := testManager(t)
	issued := issue(t, manager, "alice")

	var (
		retained *auth.Identity
		copied   auth.Identity
	)

	if err := manager.WithIdentity(
		context.Background(),
		"invalid",
		func(context.Context, *auth.Identity) error {
			t.Fatal("invalid token issued identity")

			return nil
		},
	); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatal(err)
	}

	err := manager.WithIdentity(
		context.Background(),
		issued.Token,
		func(ctx context.Context, identity *auth.Identity) error {
			retained = identity
			copied = *identity

			return identity.Use(
				ctx,
				func(ctx context.Context, subject string) error {
					if subject != "alice" {
						t.Fatalf("subject=%s", subject)
					}

					return copied.Use(
						ctx,
						func(context.Context, string) error { return nil },
					)
				},
			)
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, identity := range []*auth.Identity{nil, {}, retained, &copied} {
		if err := identity.Use(
			context.Background(),
			func(context.Context, string) error {
				t.Fatal("invalid identity executed")

				return nil
			},
		); !errors.Is(
			err,
			auth.ErrUnauthenticated,
		) {
			t.Fatal(err)
		}
	}

	*now = now.Add(time.Hour)

	if err := manager.WithIdentity(
		context.Background(),
		issued.Token,
		func(context.Context, *auth.Identity) error {
			t.Fatal("expired session executed")

			return nil
		},
	); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatal(err)
	}
}

func TestIdentityRevalidates(t *testing.T) {
	manager, _ := testManager(t)
	issued := issue(t, manager, "alice")

	err := manager.WithIdentity(
		context.Background(),
		issued.Token,
		func(ctx context.Context, identity *auth.Identity) error {
			if err := manager.Revoke(ctx, issued.Token); err != nil {
				t.Fatal(err)
			}

			return identity.Use(ctx, func(context.Context, string) error {
				t.Fatal("revoked identity executed")

				return nil
			})
		},
	)
	if !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal(err)
	}

	issued = issue(t, manager, "alice")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = manager.WithIdentity(
		ctx,
		issued.Token,
		func(_ context.Context, identity *auth.Identity) error {
			cancel()

			return identity.Use(
				context.Background(),
				func(context.Context, string) error {
					t.Fatal("canceled identity executed")

					return nil
				},
			)
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestIdentityIssuerAndCurrentExpiry(t *testing.T) {
	manager, now := testManager(t)
	other, _ := testManager(t)
	issued := issue(t, manager, "alice")

	err := manager.WithIdentity(
		context.Background(),
		issued.Token,
		func(ctx context.Context, identity *auth.Identity) error {
			if err := other.UseIdentity(
				ctx,
				identity,
				func(context.Context, string) error {
					t.Fatal("foreign manager accepted identity")

					return nil
				},
			); !errors.Is(
				err,
				auth.ErrUnauthenticated,
			) {
				t.Fatal(err)
			}

			*now = now.Add(time.Hour)

			return manager.UseIdentity(
				ctx,
				identity,
				func(context.Context, string) error {
					t.Fatal("expired identity ran")

					return nil
				},
			)
		},
	)
	if !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal(err)
	}
}
