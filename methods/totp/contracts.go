package totp

import (
	"context"
	"errors"
	"time"

	auth "github.com/plutoframework/pluto-auth"
)

var (
	ErrDenied      = errors.New("totp: invalid or expired proof")
	ErrConfig      = errors.New("totp: invalid configuration")
	ErrLimited     = errors.New("totp: request limited")
	ErrUnavailable = errors.New("totp: unavailable")
)

type Action string

const (
	SignIn     Action = "signin"
	Enroll     Action = "enroll"
	Replace    Action = "replace"
	Remove     Action = "remove"
	Regenerate Action = "regenerate"
)

// Protector is a host-owned authenticated-encryption/key-management boundary.
// Implementations MUST bind ciphertext to subject and purpose, support durable
// key IDs/rotation, honor cancellation and never log seeds or plaintext errors.
// Losing keys locks out TOTP users; recovery codes remain usable.
type Protector interface {
	Seal(context.Context, string, []byte) ([]byte, error)
	Open(context.Context, string, []byte) ([]byte, error)
}

type Limiter interface {
	Allow(context.Context, string) error
}

// Factor is internal persistence data, never a public response.
type Factor struct {
	Generation    string `json:"-"`
	EncryptedSeed []byte `json:"-"`
	LastStep      int64  `json:"-"`
}

// Pending is purpose/account/browser/version bound and never a session.
// Persistence retains only digests of the challenge and browser secrets.
type Pending struct {
	Digest    auth.Digest       `json:"-"`
	Browser   auth.Digest       `json:"-"`
	Account   auth.AccountState `json:"-"`
	Action    Action            `json:"-"`
	Primary   auth.Method       `json:"-"`
	PrimaryAt time.Time         `json:"-"`
	Expires   time.Time         `json:"-"`
	Candidate Factor            `json:"-"`
}

// Commit is a typed atomic command. The adapter locks the account before
// rechecking pending purpose/browser/version/deadlines, factor generation,
// replay counter or recovery digest. It consumes the challenge and proof in the
// SAME transaction as session creation or factor mutation. Failure changes none.
// SignIn preserves policy/version; all other actions advance version, revoke
// sessions and password challenges, and invalidate outstanding MFA challenges.
// Enroll/Replace enable required-factor policy; Remove explicitly disables it.
type Commit struct {
	Pending            Pending
	ExpectedGeneration string
	Step               int64
	Recovery           auth.Digest
	NewStep            int64
	RecoveryDigests    []auth.Digest
	Session            auth.Session
	SessionDigest      auth.Digest
}

type Store interface {
	auth.AccountSessionStore
	Save(context.Context, Pending) error
	Load(context.Context, auth.Digest, auth.Digest, time.Time) (Pending, error)
	Factor(context.Context, string) (Factor, error)
	Commit(context.Context, Commit) error
}

type Config struct {
	Sessions auth.Config
	Issuer   string

	// Changed runs after commit, without secret material. Hosts should notify
	// users through an independently verified channel. Failure cannot undo commit.
	Changed func(context.Context, string, Action)
}

// Setup contains a NEW seed URI, returned once. Never log/cache/JSON an entire
// service value. Existing seeds are never returned by this API.
type Setup struct {
	Challenge string    `json:"challenge"`
	URI       string    `json:"uri,omitempty"`
	Expires   time.Time `json:"expires"`
}

type Result struct {
	Issued        auth.IssuedSession `json:"-"`
	RecoveryCodes []string           `json:"-"`
}
