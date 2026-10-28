package password

import (
	"context"
	"errors"
	"testing"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

type credentialStore struct {
	credential Credential
	err        error
	lookups    int
}

func (s *credentialStore) Lookup(context.Context, string) (Credential, error) {
	s.lookups++

	return s.credential, s.err
}

type limiter struct {
	err error
}

func (l limiter) Allow(context.Context, string) error {
	return l.err
}

func TestSignInDecisions(t *testing.T) {
	ctx := context.Background()
	hasher := testHasher(t)

	encoded, err := hasher.Hash(ctx, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}

	store := &credentialStore{}
	sessions, _ := memory.New(10)
	manager, _ := auth.New(sessions, auth.DefaultConfig())

	authenticator, err := NewAuthenticator(
		ctx,
		store,
		hasher,
		manager,
		limiter{},
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		credential Credential
		lookupErr  error
		password   string
		accepted   bool
	}{
		{
			"valid",
			Credential{SubjectID: "alice", Hash: encoded},
			nil, "correct horse battery staple", true,
		},
		{
			"wrong password",
			Credential{SubjectID: "alice", Hash: encoded},
			nil, "wrong password", false,
		},
		{
			"unknown account",
			Credential{},
			auth.ErrNotFound,
			"correct horse battery staple", false,
		},
		{"disabled", Credential{
			SubjectID: "alice", Hash: encoded, Disabled: true,
		}, nil, "correct horse battery staple", false},
		{
			"missing subject",
			Credential{Hash: encoded},
			nil, "correct horse battery staple", false,
		},
		{
			"lookup outage",
			Credential{},
			errors.New("unavailable"),
			"correct horse battery staple", false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store.credential = test.credential
			store.err = test.lookupErr

			issued, err := authenticator.SignIn(
				ctx,
				"alice",
				[]byte(test.password),
			)
			if (err == nil) != test.accepted {
				t.Fatalf("accepted=%v, err=%v", test.accepted, err)
			}

			if test.accepted {
				verified, err := manager.Authenticate(ctx, issued.Token)
				if err != nil || verified.SubjectID != "alice" {
					t.Fatal(
						"sign-in did not establish a usable subject session",
					)
				}
			} else if issued.Token != "" {
				t.Fatal("failed sign-in issued a token")
			}
		})
	}
}

func TestLimiterRequiredAndEnforced(t *testing.T) {
	ctx := context.Background()
	hasher := testHasher(t)
	store := &credentialStore{}
	sessions, _ := memory.New(10)

	manager, _ := auth.New(sessions, auth.DefaultConfig())
	if _, err := NewAuthenticator(
		ctx,
		store,
		hasher,
		manager,
		nil,
	); err == nil {
		t.Fatal("missing limiter accepted")
	}

	denied := errors.New("rate limited")

	authenticator, err := NewAuthenticator(ctx, store, hasher,
		manager, limiter{err: denied})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := authenticator.SignIn(
		ctx,
		"alice",
		[]byte("password"),
	); !errors.Is(
		err,
		denied,
	) {
		t.Fatal("limiter failure ignored")
	}

	if store.lookups != 0 {
		t.Fatal("limited request reached credential store")
	}
}
