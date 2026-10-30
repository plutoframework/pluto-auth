package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

type fencedSessions struct {
	auth.SessionStore
	account auth.AccountState
}

func (store *fencedSessions) CreateAuthenticated(
	ctx context.Context, digest auth.Digest, session auth.Session,
) error {
	if err := store.account.Accepts(session); err != nil {
		return err
	}

	return store.Create(ctx, digest, session)
}

func complete(
	t *testing.T,
	account auth.AccountState,
	now time.Time,
) auth.Authentication {
	t.Helper()

	ceremony, err := auth.NewCeremony(account, false, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	ceremony, err = ceremony.PrimaryVerified(auth.MethodPassword, now)
	if err != nil {
		t.Fatal(err)
	}

	if account.SecondFactorRequired {
		ceremony, err = ceremony.SecondFactorVerified(auth.MethodTOTP, now)
		if err != nil {
			t.Fatal(err)
		}
	}

	proof, err := ceremony.Complete(now)
	if err != nil {
		t.Fatal(err)
	}

	return proof
}

func TestCeremonyRequiresVerifiedPrimaryAndFactor(t *testing.T) {
	now := time.Now().UTC()
	account := auth.AccountState{
		SubjectID:            "account",
		Version:              1,
		SecondFactorRequired: true,
	}

	pending, err := auth.NewCeremony(account, false, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pending.Complete(
		now,
	); !errors.Is(
		err,
		auth.ErrAuthenticationRequired,
	) {
		t.Fatal("unverified primary completed")
	}

	if _, err := pending.SecondFactorVerified(
		auth.MethodTOTP,
		now,
	); err == nil {
		t.Fatal("accepted factor before primary")
	}

	if _, err := pending.PrimaryVerified(auth.MethodTOTP, now); err == nil {
		t.Fatal("second factor substituted for primary")
	}

	primary, err := pending.PrimaryVerified(auth.MethodPassword, now)
	if err != nil {
		t.Fatal(err)
	}

	if primary.Stage() != auth.AwaitingFactor ||
		pending.Stage() != auth.AwaitingPrimary {
		t.Fatal("incorrect stage or mutated original decision")
	}

	if _, err := primary.Complete(
		now,
	); !errors.Is(
		err,
		auth.ErrAuthenticationRequired,
	) {
		t.Fatal("primary-only decision became a session proof")
	}

	if _, err := primary.SecondFactorVerified(
		auth.MethodPassword,
		now,
	); err == nil {
		t.Fatal("password reused as the second factor")
	}

	if _, err := primary.SecondFactorVerified(
		auth.MethodTOTP,
		now.Add(time.Minute),
	); !errors.Is(
		err,
		auth.ErrCeremonyExpired,
	) {
		t.Fatal("ceremony accepted factor at expiration")
	}

	if _, err := auth.NewCeremony(
		auth.AccountState{SubjectID: "disabled", Version: 1, Disabled: true},
		false,
		now,
		time.Minute,
	); err == nil {
		t.Fatal("disabled account began a ceremony")
	}
}

func TestAuthenticatedRotationPreservesFreshness(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	verifiedAt := now
	account := auth.AccountState{
		SubjectID:            "account",
		Version:              1,
		SecondFactorRequired: true,
	}

	memoryStore, err := memory.New(8)
	if err != nil {
		t.Fatal(err)
	}

	store := &fencedSessions{SessionStore: memoryStore, account: account}
	config := auth.DefaultConfig()
	config.Clock = func() time.Time { return now }

	manager, err := auth.New(store, config)
	if err != nil {
		t.Fatal(err)
	}

	issued, err := manager.StartAuthenticated(ctx, complete(t, account, now))
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(5 * time.Minute)

	rotated, err := manager.Rotate(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}

	if !rotated.Session.Authentication.PrimaryAt.Equal(verifiedAt) ||
		!rotated.Session.Authentication.SecondFactorAt.Equal(verifiedAt) {
		t.Fatal("rotation manufactured fresh authentication")
	}

	if err := manager.CheckAuthentication(rotated.Session, auth.Requirement{
		MaxAge: 5 * time.Minute, SecondFactor: true,
	}); !errors.Is(err, auth.ErrAuthenticationRequired) {
		t.Fatal("freshness boundary was extended by rotation")
	}

	store.account.Version++

	if _, err := manager.StartAuthenticated(
		ctx,
		complete(t, account, now),
	); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatal("stale account decision issued a session")
	}
}

func TestAuthenticatedIssuanceRejectsUnsupportedAndExpiredProofs(t *testing.T) {
	now := time.Now().UTC()

	store, err := memory.New(8)
	if err != nil {
		t.Fatal(err)
	}

	config := auth.DefaultConfig()
	config.Clock = func() time.Time { return now }

	manager, err := auth.New(store, config)
	if err != nil {
		t.Fatal(err)
	}

	proof := complete(
		t,
		auth.AccountState{SubjectID: "account", Version: 1},
		now,
	)
	if _, err := manager.StartAuthenticated(
		context.Background(),
		proof,
	); !errors.Is(
		err,
		auth.ErrInvalidConfig,
	) {
		t.Fatal("session-only store accepted account proof")
	}

	now = now.Add(time.Minute)

	if _, err := manager.StartAuthenticated(
		context.Background(),
		proof,
	); !errors.Is(
		err,
		auth.ErrAuthenticationRequired,
	) {
		t.Fatal("expired decision accepted")
	}

	legacy, err := manager.StartVersioned(context.Background(), "account", 1)
	if err != nil {
		t.Fatal(err)
	}

	if err := manager.CheckAuthentication(
		legacy.Session,
		auth.Requirement{MaxAge: time.Hour},
	); !errors.Is(
		err,
		auth.ErrAuthenticationRequired,
	) {
		t.Fatal("unknown legacy evidence satisfied a freshness gate")
	}
}

func TestEvidenceRequirements(t *testing.T) {
	now := time.Now().UTC()

	primary := auth.Evidence{Primary: auth.MethodPassword, PrimaryAt: now}
	if err := primary.Check(
		auth.Requirement{SecondFactor: true},
		now,
	); !errors.Is(
		err,
		auth.ErrAuthenticationRequired,
	) {
		t.Fatal("primary-only evidence satisfied a required factor")
	}

	future := primary
	future.PrimaryAt = now.Add(time.Second)

	if err := future.Check(auth.Requirement{}, now); err == nil {
		t.Fatal("future authentication accepted")
	}

	if err := primary.Check(
		auth.Requirement{MaxAge: -time.Second},
		now,
	); !errors.Is(
		err,
		auth.ErrInvalidConfig,
	) {
		t.Fatal("invalid freshness policy accepted")
	}
}

func FuzzCeremonyTransitions(f *testing.F) {
	f.Add("password", "totp", int64(1), true)
	f.Add("totp", "password", int64(600), false)
	f.Fuzz(
		func(t *testing.T, primary, factor string, offset int64, required bool) {
			now := time.Unix(1_800_000_000, 0).UTC()
			account := auth.AccountState{
				SubjectID:            "account",
				Version:              1,
				SecondFactorRequired: required,
			}

			ceremony, err := auth.NewCeremony(account, false, now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}

			primaryDecision, err := ceremony.PrimaryVerified(
				auth.Method(primary),
				now,
			)
			if err != nil {
				return
			}

			at := now.Add(time.Duration(offset%1000) * time.Second)

			final, factorErr := primaryDecision.SecondFactorVerified(
				auth.Method(factor),
				at,
			)
			if factorErr == nil {
				if !required || at.Before(now) ||
					!at.Before(now.Add(time.Minute)) ||
					factor != "totp" && factor != "recovery_code" {
					t.Fatal("invalid factor transition accepted")
				}

				if _, err := final.Complete(at); err != nil {
					t.Fatal("valid complete decision rejected")
				}
			}

			if required {
				if _, err := primaryDecision.Complete(now); err == nil {
					t.Fatal("required factor skipped")
				}
			}
		},
	)
}
