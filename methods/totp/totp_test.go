package totp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
)

func TestVectorsAndWindow(t *testing.T) {
	seed := []byte("12345678901234567890")

	// RFC 6238 SHA-1 vectors, reduced to the configured six digits.
	for _, v := range []struct {
		seconds int64
		code    string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	} {
		step, ok := Match(seed, v.code, time.Unix(v.seconds, 0), -1)
		if !ok || step != v.seconds/30 {
			t.Fatalf("vector %d", v.seconds)
		}

		if _, ok := Match(seed, v.code, time.Unix(v.seconds, 0), step); ok {
			t.Fatal("replay")
		}
	}

	now := time.Unix(1234567890, 0)
	for delta := int64(-2); delta <= 2; delta++ {
		_, ok := Match(seed, hotp(seed, now.Unix()/30+delta), now, -1)
		if ok != (delta >= -1 && delta <= 1) {
			t.Fatalf("window %d", delta)
		}
	}

	for _, code := range []string{"", "12345", "1234567", "abcdef", "１２３４５６"} {
		if _, ok := Match(seed, code, now, -1); ok {
			t.Fatal("malformed OTP")
		}
	}

	if _, ok := Match(seed, "287082", time.Unix(-1, 0), -1); ok {
		t.Fatal("negative clock")
	}
}

func TestProtection(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{7}, 32)

	protector, err := NewAESProtector(1, map[uint32][]byte{1: key})
	if err != nil {
		t.Fatal(err)
	}

	seed := []byte("12345678901234567890")

	encrypted, err := protector.Seal(ctx, "account", seed)
	if err != nil || bytes.Contains(encrypted, seed) {
		t.Fatal("plaintext protection")
	}

	plain, err := protector.Open(ctx, "account", encrypted)
	if err != nil || !bytes.Equal(plain, seed) {
		t.Fatal("roundtrip")
	}

	if _, err := protector.Open(ctx, "other", encrypted); err == nil {
		t.Fatal("account binding")
	}

	encrypted[len(encrypted)-1] ^= 1
	if _, err := protector.Open(ctx, "account", encrypted); err == nil {
		t.Fatal("tampering")
	}

	if _, err := NewAESProtector(
		1,
		map[uint32][]byte{1: make([]byte, 32)},
	); err == nil {
		t.Fatal("empty key")
	}

	ctx, cancel := context.WithCancel(ctx)
	cancel()

	if _, err := protector.Seal(
		ctx,
		"account",
		seed,
	); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatal(err)
	}
}

type testStore struct {
	auth.AccountSessionStore
	pending Pending
	factor  Factor
	command Commit
	commits int
}

func (s *testStore) Save(
	_ context.Context,
	p Pending,
) error {
	s.pending = p
	return nil
}

func (s *testStore) Load(
	_ context.Context,
	d, b auth.Digest,
	now time.Time,
) (Pending, error) {
	if d != s.pending.Digest || b != s.pending.Browser ||
		!now.Before(s.pending.Expires) {
		return Pending{}, ErrDenied
	}

	return s.pending, nil
}

func (s *testStore) Factor(context.Context, string) (Factor, error) {
	if s.factor.Generation == "" {
		return Factor{}, auth.ErrNotFound
	}

	return s.factor, nil
}

func (s *testStore) Commit(
	_ context.Context,
	c Commit,
) error {
	s.command = c
	s.commits++

	return nil
}

type testLimiter struct {
	blocked bool
	keys    []string
}

func (l *testLimiter) Allow(_ context.Context, key string) error {
	l.keys = append(l.keys, key)
	if l.blocked {
		return ErrLimited
	}

	return nil
}

func TestEnrollmentAndLimiting(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store := &testStore{}
	limiter := &testLimiter{}
	protector, _ := NewAESProtector(
		1,
		map[uint32][]byte{1: bytes.Repeat([]byte{7}, 32)},
	)
	cfg := auth.DefaultConfig()
	cfg.Clock = func() time.Time { return now }

	service, err := New(
		store,
		protector,
		limiter,
		Config{Issuer: "Example", Sessions: cfg},
	)
	if err != nil {
		t.Fatal(err)
	}

	ceremony, _ := auth.NewCeremony(
		auth.AccountState{SubjectID: "account", Version: 1},
		false,
		now,
		5*time.Minute,
	)
	ceremony, _ = ceremony.PrimaryVerified(auth.MethodPassword, now)
	browser := Browser()

	setup, err := service.Begin(
		ctx,
		ceremony,
		browser,
		Enroll,
		"user@example.com",
	)
	if err != nil || !strings.HasPrefix(setup.URI, "otpauth://totp/") {
		t.Fatal(err)
	}

	seed, err := protector.Open(
		ctx,
		"account",
		store.pending.Candidate.EncryptedSeed,
	)
	if err != nil {
		t.Fatal(err)
	}

	code := hotp(seed, now.Unix()/30)
	if _, err := service.Finish(
		ctx,
		setup.Challenge,
		Browser(),
		"",
		false,
		code,
	); !errors.Is(
		err,
		ErrDenied,
	) {
		t.Fatal("browser binding")
	}

	limiter.blocked = true

	if _, err := service.Finish(
		ctx,
		setup.Challenge,
		browser,
		"",
		false,
		code,
	); !errors.Is(
		err,
		ErrLimited,
	) {
		t.Fatal("limiter bypass")
	}

	limiter.blocked = false

	result, err := service.Finish(
		ctx,
		setup.Challenge,
		browser,
		"",
		false,
		code,
	)
	if err != nil || len(result.RecoveryCodes) != 10 || store.commits != 1 {
		t.Fatal(err)
	}

	if store.command.NewStep != now.Unix()/30 {
		t.Fatal("confirmation counter")
	}

	for i, value := range result.RecoveryCodes {
		if !secret(value) ||
			store.command.RecoveryDigests[i] != digest(
				"recovery/account",
				value,
			) {
			t.Fatal("recovery separation")
		}
	}

	for _, key := range limiter.keys {
		if key != limiter.keys[0] {
			t.Fatal("account limiter changed")
		}
	}

	data, _ := json.Marshal(store.pending)
	if string(data) != "{}" {
		t.Fatal("pending secrets exposed")
	}

	data, _ = json.Marshal(result)
	if string(data) != "{}" {
		t.Fatal("result secrets exposed")
	}

	now = now.Add(5 * time.Minute)

	if _, err := service.Finish(
		ctx,
		setup.Challenge,
		browser,
		"",
		false,
		code,
	); !errors.Is(
		err,
		ErrDenied,
	) {
		t.Fatal("expiry boundary")
	}

	if _, err := service.Begin(
		ctx,
		ceremony,
		browser,
		Enroll,
		"label",
	); !errors.Is(
		err,
		ErrDenied,
	) {
		t.Fatal("stale primary")
	}
}

func FuzzMatch(f *testing.F) {
	f.Add("123456", int64(1234567890), int64(-1))
	f.Fuzz(func(t *testing.T, code string, seconds, last int64) {
		step, ok := Match(
			[]byte("12345678901234567890"),
			code,
			time.Unix(seconds, 0),
			last,
		)
		if ok &&
			(step <= last || step < seconds/30-1 || step > seconds/30+1 || len(code) != 6) {
			t.Fatal("invalid acceptance")
		}
	})
}
