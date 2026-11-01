package auth_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

type cancelIdentityStore struct {
	auth.SessionStore
	block   atomic.Bool
	started chan struct{}
}

func (s *cancelIdentityStore) Use(
	ctx context.Context,
	digest auth.Digest,
	now time.Time,
	idle time.Duration,
) (auth.Session, error) {
	if s.block.Load() {
		close(s.started)
		<-ctx.Done()

		return auth.Session{}, ctx.Err()
	}

	return s.SessionStore.Use(ctx, digest, now, idle)
}

func TestIdentityOriginalCancellationReachesActiveUse(t *testing.T) {
	for _, stage := range []string{"lookup", "callback"} {
		t.Run(stage, func(t *testing.T) {
			memoryStore, err := memory.New(10)
			if err != nil {
				t.Fatal(err)
			}

			store := &cancelIdentityStore{
				SessionStore: memoryStore,
				started:      make(chan struct{}),
			}

			manager, err := auth.New(store, auth.DefaultConfig())
			if err != nil {
				t.Fatal(err)
			}

			issued := issue(t, manager, "alice")

			original, cancelOriginal := context.WithCancel(t.Context())
			defer cancelOriginal()

			independent, cancelUse := context.WithCancel(context.Background())
			defer cancelUse()

			done := make(chan error, 1)
			go func() {
				done <- manager.WithIdentity(
					original,
					issued.Token,
					func(_ context.Context, identity *auth.Identity) error {
						store.block.Store(stage == "lookup")

						return identity.Use(
							independent,
							func(ctx context.Context, _ string) error {
								close(store.started)
								<-ctx.Done()

								return ctx.Err()
							},
						)
					},
				)
			}()

			select {
			case <-store.started:
			case <-time.After(2 * time.Second):
				cancelUse()
				t.Fatal("use did not reach blocking dependency")
			}

			cancelOriginal()

			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled active use returned %v", err)
				}
			case <-time.After(time.Second):
				cancelUse()
				<-done
				t.Fatal("original cancellation did not release active use")
			}
		})
	}
}
