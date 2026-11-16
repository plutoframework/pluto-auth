package device

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	auth "github.com/plutoframework/pluto-auth"
)

// Grant types accepted by the token endpoint.
const (
	GrantDeviceCode   = "urn:ietf:params:oauth:grant-type:device_code"
	GrantRefreshToken = "refresh_token"
)

// Authorization states.
const (
	StatePending  = "pending"
	StateApproved = "approved"
	StateDenied   = "denied"
)

// Poll outcomes.
type PollState int

const (
	PollPending PollState = iota + 1
	PollSlowDown
	PollDenied
	PollIssued
)

// Store errors. Implementations must return exactly these.
var (
	ErrNotFound = errors.New("device: not found")
	ErrExpired  = errors.New("device: expired")
	ErrConflict = errors.New("device: conflict")
	ErrScope    = errors.New("device: scope not permitted")

	// ErrReuse reports a rotated refresh token presented again. The store has
	// already revoked the whole family atomically.
	ErrReuse = errors.New("device: refresh token reuse")
)

var scopePattern = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,63}$`)

// ValidScope reports whether name is a well formed scope name.
func ValidScope(name string) bool {
	return scopePattern.MatchString(name)
}

// Client is a declared public client. There are no client secrets: possession
// of the device code and the owner's approval authorize a grant.
type Client struct {
	ID        string
	Name      string
	ActorType string
	Scopes    []string
}

// Config is explicit. Zero durations take the documented defaults.
type Config struct {
	Clients []Client

	// Sessions is the issuer of browser sessions that may approve a request.
	Sessions *auth.Manager

	// Authorizer verifies the approving subject may delegate in the tenant.
	Authorizer Authorizer

	// Limiter bounds user-code lookups and decisions per subject. Required.
	Limiter Limiter

	VerificationURI string
	CodeTTL         time.Duration // default 10m
	PollInterval    time.Duration // default 5s
	SlowDownStep    time.Duration // default 5s
	AccessTTL       time.Duration // default 15m
	RefreshTTL      time.Duration // default 30d, each refresh token
	MaxLifetime     time.Duration // default 90d, absolute per grant
	Clock           func() time.Time
}

// Authorizer decides whether subject may delegate scopes in tenant. It must
// verify live membership; a header or request field is never proof.
type Authorizer interface {
	AuthorizeDelegation(
		ctx context.Context,
		subject, tenant string,
		scopes []string,
	) error
}

// Limiter must fail closed and be shared across replicas in production.
type Limiter interface {
	Allow(ctx context.Context, key string) error
}

// Authorization is one pending device request. Codes are stored as digests.
type Authorization struct {
	ID         string
	Device     auth.Digest
	User       auth.Digest
	ClientID   string
	Scopes     []string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastPolled time.Time
	Interval   time.Duration
	State      string
	Subject    string
	Tenant     string
	Approved   []string
}

// Decision is the owner's answer. Scopes must be a subset of the request.
type Decision struct {
	Approve bool
	Subject string
	Tenant  string
	Scopes  []string
}

// Redemption carries pre-generated token material for a device-code poll.
type Redemption struct {
	ClientID       string
	Step           time.Duration
	GrantID        string
	ActorType      string
	AccessID       string
	Access         auth.Digest
	AccessExpires  time.Time
	Refresh        auth.Digest
	RefreshExpires time.Time
	MaxLifetime    time.Duration
}

// Rotation carries pre-generated material for a refresh-token exchange.
type Rotation struct {
	ClientID       string
	Narrow         []string
	AccessID       string
	Access         auth.Digest
	AccessExpires  time.Time
	Refresh        auth.Digest
	RefreshExpires time.Time
}

// PollResult is the outcome of one device-code poll.
type PollResult struct {
	State    PollState
	Interval time.Duration
	Grant    Grant
}

// Grant is a token family: one approval and everything rotated from it.
type Grant struct {
	ID        string
	Subject   string
	Tenant    string
	ClientID  string
	ActorType string
	Scopes    []string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt time.Time
}

// Active reports whether the family may still authenticate.
func (g Grant) Active(now time.Time) bool {
	return g.RevokedAt.IsZero() && now.Before(g.ExpiresAt)
}

// Delegation returns the session metadata for the family.
func (g Grant) Delegation() *auth.Delegation {
	return &auth.Delegation{
		GrantID:   g.ID,
		ClientID:  g.ClientID,
		ActorType: g.ActorType,
		Tenant:    g.Tenant,
		Scopes:    slices.Clone(g.Scopes),
	}
}

// Token is an access token's lookup result.
type Token struct {
	ID        string
	ExpiresAt time.Time
}

// Store persists authorizations and token families. Every method is atomic and
// concurrency safe. Only digests of device codes, user codes and tokens are
// stored.
type Store interface {

	// CreateAuthorization returns ErrConflict if the user-code or device-code
	// digest is already in use by an unexpired authorization.
	CreateAuthorization(context.Context, Authorization) error

	FindAuthorization(
		context.Context,
		auth.Digest,
		time.Time,
	) (Authorization, error)

	// Decide moves a pending, unexpired authorization to approved or denied.
	// A subset check of Decision.Scopes against the request is enforced
	// (ErrScope). Otherwise a missing or non-pending request is ErrNotFound.
	Decide(context.Context, auth.Digest, time.Time, Decision) error

	// Poll implements polling, slow_down and single-use redemption. The
	// authorization is deleted when it is denied or redeemed. A client
	// mismatch is ErrNotFound; expiry is ErrExpired.
	Poll(
		context.Context,
		auth.Digest,
		time.Time,
		Redemption,
	) (PollResult, error)

	// Rotate consumes a refresh token, revokes the prior access tokens of
	// the family and issues the replacement pair. A used token revokes the
	// family and returns ErrReuse. Unknown, expired and revoked are
	// ErrNotFound. Narrow, when set, must be a subset (ErrScope) and
	// permanently narrows the family.
	Rotate(context.Context, auth.Digest, time.Time, Rotation) (Grant, error)

	// Access returns the family of an unexpired access token of an active
	// grant, else ErrNotFound.
	Access(context.Context, auth.Digest, time.Time) (Grant, Token, error)

	// RevokeToken revokes the family of an access or refresh token. Unknown
	// tokens are not an error.
	RevokeToken(context.Context, auth.Digest) error

	// RevokeGrant revokes one family owned by subject; others are ErrNotFound.
	RevokeGrant(ctx context.Context, subject, id string) error
	RevokeSubject(ctx context.Context, subject string) error

	ListGrants(context.Context, string, time.Time) ([]Grant, error)
	Prune(context.Context, time.Time) (int64, error)
}

// Error is an RFC 8628/6749 error response.
type Error struct {
	Code        string
	Status      int
	Description string
}

func (e *Error) Error() string {
	return fmt.Sprintf("device: %s", e.Code)
}

var (
	ErrAuthorizationPending = &Error{Code: "authorization_pending", Status: 400}
	ErrSlowDown             = &Error{Code: "slow_down", Status: 400}
	ErrAccessDenied         = &Error{Code: "access_denied", Status: 400}
	ErrExpiredToken         = &Error{Code: "expired_token", Status: 400}
	ErrInvalidGrant         = &Error{Code: "invalid_grant", Status: 400}
	ErrInvalidRequest       = &Error{Code: "invalid_request", Status: 400}
	ErrInvalidClient        = &Error{Code: "invalid_client", Status: 401}
	ErrInvalidScope         = &Error{Code: "invalid_scope", Status: 400}
	ErrUnsupportedGrant     = &Error{
		Code:   "unsupported_grant_type",
		Status: 400,
	}
	ErrRateLimited = &Error{Code: "rate_limited", Status: 429}
	ErrForbidden   = &Error{Code: "forbidden", Status: 403}
)
