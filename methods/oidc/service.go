package oidc

import (
	"context"
	"time"

	auth "github.com/plutoframework/pluto-auth"
)

// Accounts resolves a verified issuer/subject, never an email-based merge.
// Resolve/create and uniqueness checks must be atomic. Enrollment is explicit.
type Accounts interface {
	ResolveIdentity(context.Context, Identity, bool) (auth.AccountState, error)
}

type Service struct {
	client   *Client
	accounts Accounts
	sessions *auth.Manager
	enroll   bool
}

func NewService(client *Client, accounts Accounts, sessions *auth.Manager,
	allowEnrollment bool,
) (*Service, error) {
	if client == nil || accounts == nil || sessions == nil {
		return nil, ErrConfig
	}

	return &Service{
		client: client, accounts: accounts, sessions: sessions,
		enroll: allowEnrollment,
	}, nil
}

func (s *Service) Issuer() string { return s.client.issuer }

func (s *Service) Sessions() *auth.Manager { return s.sessions }
func (s *Service) Begin(ctx context.Context, browser string) (string, error) {
	return s.client.Begin(ctx, browser)
}

// SignIn fails closed when another factor is required. No pending ceremony is
// serialized into a browser cookie and no ordinary session bypasses MFA policy.
func (s *Service) SignIn(
	ctx context.Context,
	state, browser, code string,
) (auth.IssuedSession, error) {
	identity, err := s.client.Complete(ctx, state, browser, code)
	if err != nil {
		return auth.IssuedSession{}, ErrDenied
	}

	account, err := s.accounts.ResolveIdentity(ctx, identity, s.enroll)
	if err != nil {
		return auth.IssuedSession{}, ErrDenied
	}

	now := s.client.clock()

	ceremony, err := auth.NewCeremony(account, false, now, time.Minute)
	if err != nil {
		return auth.IssuedSession{}, ErrDenied
	}

	ceremony, err = ceremony.PrimaryVerified(auth.MethodOIDC, now)
	if err != nil {
		return auth.IssuedSession{}, ErrDenied
	}

	proof, err := ceremony.Complete(s.client.clock())
	if err != nil {
		return auth.IssuedSession{}, ErrDenied
	}

	issued, err := s.sessions.StartAuthenticated(ctx, proof)
	if err != nil {
		return auth.IssuedSession{}, ErrDenied
	}

	return issued, nil
}
