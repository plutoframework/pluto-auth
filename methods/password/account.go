package password

import (
	"context"
	"errors"
	"time"

	auth "github.com/plutoframework/pluto-auth"
)

var (
	ErrInvalidEmail     = errors.New("password: invalid email")
	ErrInvalidChallenge = errors.New("password: invalid or expired challenge")
	ErrConflict         = errors.New("password: account already exists")
	ErrLimited          = errors.New("password: request limited")
	ErrUnavailable      = errors.New("password: service unavailable")
	ErrDelivery         = errors.New("password: notification delivery failed")
	ErrPasswordPolicy   = errors.New("password: password rejected by policy")
)

type Purpose string

const (
	VerifyEmail     Purpose = "verify_email"
	RecoverPassword Purpose = "recover_password"
)

// Account is auth-owned credential state, never application profile or RBAC.
// It is internal service/storage data, not a public API response.
type Account struct {
	ID                   string `json:"-"`
	Email                string `json:"-"`
	Hash                 string `json:"-"`
	Version              int64  `json:"-"`
	Verified             bool   `json:"-"`
	Disabled             bool   `json:"-"`
	SecondFactorRequired bool   `json:"-"`
}

// Challenge stores only a purpose-separated digest of a random token.
type Challenge struct {
	Digest    auth.Digest
	Purpose   Purpose
	CreatedAt time.Time
	ExpiresAt time.Time
}

// AccountStore operations are atomic, cancellation-aware and concurrency safe.
// Every account mutation and versioned session Create must lock the same account
// fence. Reset and Disable increment Version, delete all challenges and revoke
// all subject sessions in the SAME transaction. Failed transactions change none
// of those records. Session rotation must retain CredentialVersion.
// Session Create MUST reject zero/mismatched CredentialVersion, unverified or
// disabled accounts under the same fence. Use/Consume return the stored version;
// Use also rejects disabled, unverified or mismatched-version bindings.
// Implementations must implement auth.SessionStore with these semantics.
type AccountStore interface {
	auth.SessionStore

	// Enroll atomically inserts account + challenge; duplicates return ErrConflict.
	Enroll(context.Context, Account, Challenge) error
	LookupAccount(context.Context, string) (Account, error)

	// ReplaceChallenge replaces the sole outstanding challenge of this purpose.
	// Reject disabled accounts; verification needs unverified, recovery verified.
	ReplaceChallenge(context.Context, string, Challenge) (Account, error)

	// ChallengeAccount checks purpose, generation, created <= now < expiry.
	ChallengeAccount(
		context.Context,
		Purpose,
		auth.Digest,
		time.Time,
	) (Account, error)

	// Verify consumes a verification challenge and marks email verified atomically.
	Verify(context.Context, auth.Digest, time.Time) error

	// Reset rechecks the challenge and expected version, consumes all challenges,
	// changes the hash, increments the version and revokes sessions atomically.
	Reset(context.Context, auth.Digest, int64, string, time.Time) error

	// Disable is a trusted server operation, never an unauthenticated HTTP route.
	Disable(context.Context, string) error
}

// Notification contains sensitive delivery material. Never log/JSON encode it
// or persist it in a plaintext outbox. The application supplies a real sender.
// Delivery happens synchronously AFTER commit; failure requires a new resend.
type Notification struct {
	Email     string    `json:"-"`
	Purpose   Purpose   `json:"-"`
	Token     string    `json:"-"`
	ExpiresAt time.Time `json:"-"`
}

// Sender must be concurrency safe and honor context and delivery timeouts.
type Sender interface {
	Send(context.Context, Notification) error
}

// PasswordPolicy can check a local compromised-password corpus. No network
// dependency is required. Any error rejects the password (fail closed).
type PasswordPolicy interface {
	Check(context.Context, []byte) error
}

type LifecycleConfig struct {
	VerificationTTL time.Duration
	RecoveryTTL     time.Duration
	Clock           func() time.Time
	Policy          PasswordPolicy

	// OnDeliveryError receives a redacted sentinel, never the sender's error,
	// token, recipient or account ID. It must be concurrency safe.
	OnDeliveryError func(context.Context, error)
}

func DefaultLifecycleConfig() LifecycleConfig {
	return LifecycleConfig{
		VerificationTTL: 24 * time.Hour,
		RecoveryTTL:     30 * time.Minute,
		Clock:           time.Now,
	}
}
