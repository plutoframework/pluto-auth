package totppostgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/methods/password"
	"github.com/plutoframework/pluto-auth/methods/totp"
)

// captureStore is a deterministic barrier between verification and persistence.
// Both commands carry valid independently verified proofs of the same OTP step.
type captureStore struct {
	totp.Store
	command totp.Commit
}

func (s *captureStore) Commit(_ context.Context, c totp.Commit) error {
	s.command = c
	return totp.ErrDenied
}

func TestAtomicTOTPCounterAcrossActions(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	browser := totp.Browser()
	signin := h.begin(t, browser, totp.SignIn)
	regenerate := h.begin(t, browser, totp.Regenerate)
	captured := &captureStore{Store: h.store}

	protector, err := totp.NewAESProtector(
		1,
		map[uint32][]byte{1: bytes.Repeat([]byte{9}, 32)},
	)
	if err != nil {
		t.Fatal(err)
	}

	limiter, err := password.NewWindowLimiter(1000, 1000, time.Minute, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	service, err := totp.New(
		captured,
		protector,
		limiter,
		totp.Config{Issuer: "Test", Sessions: auth.DefaultConfig()},
	)
	if err != nil {
		t.Fatal(err)
	}

	code := otp(h.seed, time.Now().Unix()/30)
	if _, err := service.Finish(
		ctx,
		signin.Challenge,
		browser,
		code,
		false,
		"",
	); !errors.Is(
		err,
		totp.ErrDenied,
	) {
		t.Fatal(err)
	}

	first := captured.command

	if _, err := service.Finish(
		ctx,
		regenerate.Challenge,
		browser,
		code,
		false,
		"",
	); !errors.Is(
		err,
		totp.ErrDenied,
	) {
		t.Fatal(err)
	}

	second := captured.command
	if first.Step != second.Step || first.Step < 0 {
		t.Fatal("barrier did not capture matching proofs")
	}

	if err := h.store.Commit(ctx, first); err != nil {
		t.Fatal(err)
	}

	if err := h.store.Commit(ctx, second); !errors.Is(err, totp.ErrDenied) {
		t.Fatal("atomic OTP counter bypass", err)
	}
}
