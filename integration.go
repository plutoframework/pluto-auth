package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"
	"unicode"
)

// ErrInvalidIntegration reports an invalid tenant ID, principal or token ID.
var ErrInvalidIntegration = errors.New("auth: invalid integration token")

const maxIntegrationField = 256

// IntegrationToken is the persisted, non-secret description of a long-lived
// service credential. TenantID is an opaque value chosen by the trusted
// operator who issues the token, never by the calling client. Principal is a
// service-principal label. Neither value grants roles or permissions.
type IntegrationToken struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Principal string    `json:"principal"`
	CreatedAt time.Time `json:"created_at"`
}

// IntegrationStore persists integration tokens by digest only. Operations must
// honor cancellation and be concurrency safe. Lookup, Rotate and Revoke take
// effect for the very next Lookup. Lookup and Rotate report ErrNotFound for
// unknown or revoked tokens. Rotate atomically replaces the digest, so the
// previous secret stops resolving at once. Revoke is idempotent. Issue must
// reject a duplicate ID or digest.
type IntegrationStore interface {
	Issue(context.Context, Digest, IntegrationToken) error
	Lookup(context.Context, Digest) (IntegrationToken, error)
	Rotate(context.Context, string, Digest) (IntegrationToken, error)
	Revoke(context.Context, string) error
}

// IssuedIntegrationToken is returned only at issuance and rotation. Secret is
// the one and only plaintext copy: it is never persisted and must never be
// logged. Formatting and structured logging redact it.
type IssuedIntegrationToken struct {
	Token  IntegrationToken `json:"token"`
	Secret string           `json:"-"`
}

// String redacts the secret from fmt verbs such as %v and %+v.
func (i IssuedIntegrationToken) String() string {
	return fmt.Sprintf("IssuedIntegrationToken{id=%s secret=[redacted]}",
		i.Token.ID)
}

// GoString redacts the secret from the %#v verb.
func (i IssuedIntegrationToken) GoString() string { return i.String() }

// LogValue redacts the secret from log/slog output.
func (i IssuedIntegrationToken) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", i.Token.ID),
		slog.String("tenant_id", i.Token.TenantID),
		slog.String("principal", i.Token.Principal),
	)
}

// ServiceIdentity is the authenticated identity of a service caller. It is a
// distinct type from Session: it has no subject, expiry or activity, and no
// function accepting a Session accepts it. It proves a live integration token
// and its tenant/principal binding only. It grants no role, permission or
// resource access; authorize through the application's policy layer.
type ServiceIdentity struct {
	TokenID   string
	TenantID  string
	Principal string
}

// IsService always reports true. It exists so generic code can state that a
// caller is a service and not an interactive user.
func (ServiceIdentity) IsService() bool { return true }

// Integrations issues, authenticates, rotates and revokes integration tokens.
type Integrations struct {
	store IntegrationStore
	clock func() time.Time
}

// NewIntegrations copies its explicit dependencies. Clock must be concurrency
// safe.
func NewIntegrations(
	store IntegrationStore,
	clock func() time.Time,
) (*Integrations, error) {
	if store == nil || clock == nil {
		return nil, ErrInvalidConfig
	}

	return &Integrations{store: store, clock: clock}, nil
}

// Issue creates a token for an opaque tenant ID and a principal label. Call it
// only from trusted operator code; never pass client-supplied tenant IDs.
func (i *Integrations) Issue(
	ctx context.Context,
	tenantID string,
	principal string,
) (IssuedIntegrationToken, error) {
	if err := ctx.Err(); err != nil {
		return IssuedIntegrationToken{}, err
	}

	if !validIntegrationField(tenantID) || !validIntegrationField(principal) {
		return IssuedIntegrationToken{}, ErrInvalidIntegration
	}

	secret, digest, err := newIntegrationSecret()
	if err != nil {
		return IssuedIntegrationToken{}, err
	}

	token := IntegrationToken{
		ID:        rand.Text(),
		TenantID:  tenantID,
		Principal: principal,
		CreatedAt: i.clock().UTC(),
	}

	if err := i.store.Issue(ctx, digest, token); err != nil {
		return IssuedIntegrationToken{},
			fmt.Errorf("auth: issue integration token: %w", err)
	}

	return IssuedIntegrationToken{Token: token, Secret: secret}, nil
}

// Authenticate resolves a bearer secret to a service identity. Malformed,
// unknown and revoked secrets all return ErrUnauthenticated. The secret is
// never compared in application code: the store looks up its digest.
func (i *Integrations) Authenticate(
	ctx context.Context,
	secret string,
) (ServiceIdentity, error) {
	if err := ctx.Err(); err != nil {
		return ServiceIdentity{}, err
	}

	digest, err := TokenDigest(secret)
	if err != nil {
		return ServiceIdentity{}, ErrUnauthenticated
	}

	token, err := i.store.Lookup(ctx, digest)
	if errors.Is(err, ErrNotFound) {
		return ServiceIdentity{}, ErrUnauthenticated
	}

	if err != nil {
		return ServiceIdentity{},
			fmt.Errorf("auth: look up integration token: %w", err)
	}

	if token.ID == "" || token.TenantID == "" || token.Principal == "" {
		return ServiceIdentity{}, ErrUnauthenticated
	}

	return ServiceIdentity{
		TokenID:   token.ID,
		TenantID:  token.TenantID,
		Principal: token.Principal,
	}, nil
}

// Rotate replaces the secret of a live token. The old secret fails at once
// and the returned new secret works. Tenant and principal are unchanged.
// Rotating an unknown or revoked token returns ErrNotFound.
func (i *Integrations) Rotate(
	ctx context.Context,
	id string,
) (IssuedIntegrationToken, error) {
	if err := ctx.Err(); err != nil {
		return IssuedIntegrationToken{}, err
	}

	if !validIntegrationField(id) {
		return IssuedIntegrationToken{}, ErrInvalidIntegration
	}

	secret, digest, err := newIntegrationSecret()
	if err != nil {
		return IssuedIntegrationToken{}, err
	}

	token, err := i.store.Rotate(ctx, id, digest)
	if err != nil {
		return IssuedIntegrationToken{},
			fmt.Errorf("auth: rotate integration token: %w", err)
	}

	return IssuedIntegrationToken{Token: token, Secret: secret}, nil
}

// Revoke permanently disables a token. It is idempotent. Requests that were
// already authenticated are not cancelled.
func (i *Integrations) Revoke(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if !validIntegrationField(id) {
		return ErrInvalidIntegration
	}

	if err := i.store.Revoke(ctx, id); err != nil {
		return fmt.Errorf("auth: revoke integration token: %w", err)
	}

	return nil
}

func newIntegrationSecret() (string, Digest, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", Digest{}, fmt.Errorf("auth: generate token: %w", err)
	}

	secret := base64.RawURLEncoding.EncodeToString(raw)

	digest, err := TokenDigest(secret)
	if err != nil {
		return "", Digest{}, err
	}

	return secret, digest, nil
}

func validIntegrationField(value string) bool {
	if value == "" || len(value) > maxIntegrationField {
		return false
	}

	for _, r := range value {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return false
		}
	}

	return value[0] != ' ' && value[len(value)-1] != ' '
}
