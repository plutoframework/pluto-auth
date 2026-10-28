package password

import (
	"context"
	"errors"
	"fmt"

	auth "github.com/plutoframework/pluto-auth"
)

var ErrInvalidCredentials = errors.New("password: invalid credentials")

// Credential contains a password hash, never a raw password. Lookup identifiers
// and account canonicalization belong to the application, not this library.
type Credential struct {
	SubjectID string
	Hash      string `json:"-"`
	Disabled  bool
}

type CredentialStore interface {
	// Lookup returns auth.ErrNotFound for an unknown identifier.
	Lookup(context.Context, string) (Credential, error)
}

type SessionIssuer interface {
	Start(context.Context, string) (auth.IssuedSession, error)
}

// AttemptLimiter must provide bounded, shared rate limits in production.
// The application should also limit ingress by network/client identity. Never
// trust an arbitrary X-Forwarded-For header as the client identity.
type AttemptLimiter interface {
	Allow(context.Context, string) error
}

type Authenticator struct {
	store    CredentialStore
	hasher   *Hasher
	sessions SessionIssuer
	limiter  AttemptLimiter
	dummy    string
}

// NewAuthenticator requires an explicit limiter. Unknown accounts run the same
// Argon2 verification work as default-cost accounts. Store latency and accounts
// with older hash parameters can still differ; this is not a constant-time API.
func NewAuthenticator(
	ctx context.Context,
	store CredentialStore,
	hasher *Hasher,
	sessions SessionIssuer,
	limiter AttemptLimiter,
) (*Authenticator, error) {
	if store == nil || hasher == nil || sessions == nil || limiter == nil {
		return nil, ErrInvalidConfig
	}

	dummy, err := hasher.Hash(ctx, []byte("pluto-dummy-account-verification"))
	if err != nil {
		return nil, err
	}

	return &Authenticator{
		store:    store,
		hasher:   hasher,
		sessions: sessions,
		limiter:  limiter,
		dummy:    dummy,
	}, nil
}

func (a *Authenticator) SignIn(
	ctx context.Context,
	identifier string,
	password []byte,
) (auth.IssuedSession, error) {
	if err := ctx.Err(); err != nil {
		return auth.IssuedSession{}, err
	}

	if len(identifier) == 0 || len(identifier) > 256 ||
		len(password) == 0 || len(password) > MaxPasswordBytes {
		return auth.IssuedSession{}, ErrInvalidCredentials
	}

	if err := a.limiter.Allow(ctx, identifier); err != nil {
		return auth.IssuedSession{}, fmt.Errorf(
			"password: attempt limit: %w",
			err,
		)
	}

	credential, lookupErr := a.store.Lookup(ctx, identifier)
	if lookupErr != nil && !errors.Is(lookupErr, auth.ErrNotFound) {
		return auth.IssuedSession{}, fmt.Errorf(
			"password: lookup: %w",
			lookupErr,
		)
	}

	encoded := credential.Hash
	if lookupErr != nil {
		encoded = a.dummy
	}

	valid, err := a.hasher.Verify(ctx, password, encoded)
	if err != nil {
		return auth.IssuedSession{}, fmt.Errorf("password: verify: %w", err)
	}

	if !valid || lookupErr != nil || credential.Disabled ||
		credential.SubjectID == "" {
		return auth.IssuedSession{}, ErrInvalidCredentials
	}

	return a.sessions.Start(ctx, credential.SubjectID)
}
