package memory

import (
	"context"
	"errors"
	"sync"

	auth "github.com/plutoframework/pluto-auth"
)

type integrationRecord struct {
	digest  auth.Digest
	token   auth.IntegrationToken
	revoked bool
}

// IntegrationStore is a bounded, process-local auth.IntegrationStore for tests
// and single-process development. Restarts discard all tokens.
type IntegrationStore struct {
	mu       sync.Mutex
	byID     map[string]*integrationRecord
	byDigest map[auth.Digest]*integrationRecord
	capacity int
}

// NewIntegrationStore bounds retained tokens, including revoked ones.
func NewIntegrationStore(capacity int) (*IntegrationStore, error) {
	if capacity <= 0 {
		return nil, auth.ErrInvalidConfig
	}

	return &IntegrationStore{
		byID:     make(map[string]*integrationRecord),
		byDigest: make(map[auth.Digest]*integrationRecord),
		capacity: capacity,
	}, nil
}

func (s *IntegrationStore) Issue(
	ctx context.Context,
	digest auth.Digest,
	token auth.IntegrationToken,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	if _, exists := s.byID[token.ID]; exists {
		return errors.New("auth: duplicate integration token")
	}

	if _, exists := s.byDigest[digest]; exists {
		return errors.New("auth: duplicate integration token")
	}

	if len(s.byID) >= s.capacity {
		return errors.New("auth: integration token capacity reached")
	}

	record := &integrationRecord{digest: digest, token: token}
	s.byID[token.ID] = record
	s.byDigest[digest] = record

	return nil
}

func (s *IntegrationStore) Lookup(
	ctx context.Context,
	digest auth.Digest,
) (auth.IntegrationToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return auth.IntegrationToken{}, err
	}

	record, exists := s.byDigest[digest]
	if !exists || record.revoked {
		return auth.IntegrationToken{}, auth.ErrNotFound
	}

	return record.token, nil
}

func (s *IntegrationStore) Rotate(
	ctx context.Context,
	id string,
	digest auth.Digest,
) (auth.IntegrationToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return auth.IntegrationToken{}, err
	}

	record, exists := s.byID[id]
	if !exists || record.revoked {
		return auth.IntegrationToken{}, auth.ErrNotFound
	}

	if _, taken := s.byDigest[digest]; taken {
		return auth.IntegrationToken{},
			errors.New("auth: duplicate integration token")
	}

	delete(s.byDigest, record.digest)

	record.digest = digest
	s.byDigest[digest] = record

	return record.token, nil
}

func (s *IntegrationStore) Revoke(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	record, exists := s.byID[id]
	if !exists {
		return nil
	}

	record.revoked = true
	delete(s.byDigest, record.digest)

	return nil
}

var _ auth.IntegrationStore = (*IntegrationStore)(nil)
