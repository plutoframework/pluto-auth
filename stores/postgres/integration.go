package postgres

import (
	"context"
	_ "embed"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/postgres/internal/db"
)

// IntegrationSchema is optional migration 006 for service-caller integration
// tokens. It is independent of migrations 002-005; apply it explicitly. No
// constructor executes DDL.
//
//go:embed migrations/006_integration_tokens.sql
var IntegrationSchema string

// IntegrationStore implements auth.IntegrationStore. It persists only token
// digests. Every operation is a single atomic statement, so Rotate and Revoke
// are visible to the very next Lookup on any connection.
type IntegrationStore struct {
	queries *db.Queries
}

func NewIntegrationStore(database DBTX) (*IntegrationStore, error) {
	if database == nil {
		return nil, auth.ErrInvalidConfig
	}

	return &IntegrationStore{queries: db.New(database)}, nil
}

func (s *IntegrationStore) Issue(
	ctx context.Context,
	digest auth.Digest,
	token auth.IntegrationToken,
) error {
	return s.queries.InsertIntegrationToken(
		ctx,
		db.InsertIntegrationTokenParams{
			ID:          token.ID,
			TokenDigest: digest[:],
			TenantID:    token.TenantID,
			Principal:   token.Principal,
			CreatedAt:   token.CreatedAt,
		},
	)
}

func (s *IntegrationStore) Lookup(
	ctx context.Context,
	digest auth.Digest,
) (auth.IntegrationToken, error) {
	row, err := s.queries.LookupIntegrationToken(ctx, digest[:])
	if err != nil {
		return auth.IntegrationToken{}, storeError(err)
	}

	return auth.IntegrationToken{
		ID:        row.ID,
		TenantID:  row.TenantID,
		Principal: row.Principal,
		CreatedAt: row.CreatedAt,
	}, nil
}

func (s *IntegrationStore) Rotate(
	ctx context.Context,
	id string,
	digest auth.Digest,
) (auth.IntegrationToken, error) {
	row, err := s.queries.RotateIntegrationToken(
		ctx,
		db.RotateIntegrationTokenParams{ID: id, NewDigest: digest[:]},
	)
	if err != nil {
		return auth.IntegrationToken{}, storeError(err)
	}

	return auth.IntegrationToken{
		ID:        row.ID,
		TenantID:  row.TenantID,
		Principal: row.Principal,
		CreatedAt: row.CreatedAt,
	}, nil
}

func (s *IntegrationStore) Revoke(ctx context.Context, id string) error {
	return s.queries.RevokeIntegrationToken(ctx, id)
}

var _ auth.IntegrationStore = (*IntegrationStore)(nil)
