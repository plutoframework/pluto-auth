// Package oidcpostgres provides encrypted OIDC transactions and identity lookup.
package oidcpostgres

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/methods/oidc"
	"github.com/plutoframework/pluto-auth/stores/postgres"
	"github.com/plutoframework/pluto-auth/stores/postgres/internal/db"

	"github.com/jackc/pgx/v5"
)

type Store struct {
	database postgres.TransactionDB
	queries  *db.Queries
	seal     cipher.AEAD
	capacity int64
}

// New requires a 32-byte host-managed encryption key and finite shared capacity.
// Key replacement invalidates pending logins. All instances sharing a database
// must use the same key/capacity policy. No startup DDL is performed.
func New(
	database postgres.TransactionDB,
	key []byte,
	capacity int64,
) (*Store, error) {
	if database == nil || len(key) != 32 || capacity < 1 || capacity > 1000000 {
		return nil, oidc.ErrConfig
	}

	nonzero := false
	for _, b := range key {
		nonzero = nonzero || b != 0
	}

	if !nonzero {
		return nil, oidc.ErrConfig
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, oidc.ErrConfig
	}

	seal, err := cipher.NewGCM(block)
	if err != nil {
		return nil, oidc.ErrConfig
	}

	return &Store{
		database: database,
		queries:  db.New(database),
		seal:     seal,
		capacity: capacity,
	}, nil
}

func (s *Store) transaction(
	ctx context.Context,
	fn func(*db.Queries) error,
) error {
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}

	defer func() {
		rollback, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()

		_ = tx.Rollback(rollback)
	}()

	if err = fn(db.New(tx)); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Store) Save(ctx context.Context, tx oidc.Transaction) error {
	now := time.Now()
	if len(tx.State) != 43 || len(tx.Nonce) != 43 || len(tx.Verifier) < 43 ||
		len(tx.Verifier) > 128 ||
		!now.Before(tx.Expires) ||
		tx.Expires.After(now.Add(10*time.Minute)) ||
		tx.BrowserDigest == [32]byte{} {
		return oidc.ErrDenied
	}

	tx.Expires = tx.Expires.UTC().Truncate(time.Microsecond)
	digest := sha256.Sum256([]byte(tx.State))

	plain, err := json.Marshal(tx)
	if err != nil {
		return oidc.ErrDenied
	}

	nonce := make([]byte, s.seal.NonceSize())
	_, _ = rand.Read(nonce)

	aad := append(digest[:], tx.BrowserDigest[:]...)
	encrypted := s.seal.Seal(nonce, nonce, plain, aad)

	return s.transaction(ctx, func(q *db.Queries) error {
		if err := q.LockOIDCCapacity(ctx); err != nil {
			return err
		}

		if _, err := q.PruneOIDCTransactions(ctx); err != nil {
			return err
		}

		count, err := q.SaveOIDCTransaction(ctx, db.SaveOIDCTransactionParams{
			StateDigest:    digest[:],
			BrowserDigest:  tx.BrowserDigest[:],
			EncryptedProof: encrypted,
			ExpiresAt:      tx.Expires,
			Capacity:       s.capacity,
		})
		if err != nil {
			return err
		}

		if count != 1 {
			return oidc.ErrDenied
		}

		return nil
	})
}

func (s *Store) Consume(ctx context.Context, state string, browser [32]byte,
	now time.Time,
) (oidc.Transaction, error) {
	if len(state) != 43 || browser == [32]byte{} {
		return oidc.Transaction{}, oidc.ErrDenied
	}

	digest := sha256.Sum256([]byte(state))

	row, err := s.queries.ConsumeOIDCTransaction(
		ctx,
		db.ConsumeOIDCTransactionParams{
			StateDigest: digest[:], BrowserDigest: browser[:], NowAt: now,
		},
	)
	if err != nil {
		return oidc.Transaction{}, oidc.ErrDenied
	}

	n := s.seal.NonceSize()
	if len(row.EncryptedProof) < n {
		return oidc.Transaction{}, oidc.ErrDenied
	}

	aad := append(digest[:], browser[:]...)

	plain, err := s.seal.Open(
		nil,
		row.EncryptedProof[:n],
		row.EncryptedProof[n:],
		aad,
	)
	if err != nil {
		return oidc.Transaction{}, oidc.ErrDenied
	}

	var tx oidc.Transaction
	if json.Unmarshal(plain, &tx) != nil || tx.State != state ||
		tx.BrowserDigest != browser ||
		!now.Before(tx.Expires) ||
		!tx.Expires.Equal(row.ExpiresAt) {
		return oidc.Transaction{}, oidc.ErrDenied
	}

	return tx, nil
}

func (s *Store) Prune(ctx context.Context) (int64, error) {
	return s.queries.PruneOIDCTransactions(ctx)
}

// ResolveIdentity never searches by provider email. First-use enrollment creates
// an independent account with no local credentials and no business privileges.
func (s *Store) ResolveIdentity(ctx context.Context, identity oidc.Identity,
	allowEnrollment bool,
) (auth.AccountState, error) {
	issuer, subject := identity.Issuer(), identity.Subject()
	if issuer == "" || subject == "" || len(issuer) > 2048 ||
		len(subject) > 1024 {
		return auth.AccountState{}, oidc.ErrDenied
	}

	var account auth.AccountState

	err := s.transaction(ctx, func(q *db.Queries) error {
		encoded, _ := json.Marshal([]string{issuer, subject})

		digest := sha256.Sum256(encoded)
		if err := q.LockExternalIdentity(
			ctx,
			int64(binary.BigEndian.Uint64(digest[:8])),
		); err != nil {
			return err
		}

		row, err := q.LookupExternalIdentity(
			ctx,
			db.LookupExternalIdentityParams{
				Issuer: issuer, Subject: subject,
			},
		)
		if errors.Is(err, pgx.ErrNoRows) && allowEnrollment {
			id := "oidc_" + rand.Text()
			if err := q.CreateExternalAccount(ctx, id); err != nil {
				return err
			}

			if err := q.BindExternalIdentity(ctx, db.BindExternalIdentityParams{
				Issuer: issuer, Subject: subject, AccountID: id,
			}); err != nil {
				return err
			}

			account = auth.AccountState{SubjectID: id, Version: 1}

			return nil
		}

		if err != nil {
			return oidc.ErrDenied
		}

		if row.Disabled {
			return oidc.ErrDenied
		}

		account = auth.AccountState{
			SubjectID: row.ID, Version: row.CredentialVersion,
			SecondFactorRequired: row.SecondFactorRequired,
		}

		return nil
	})

	return account, err
}

var (
	_ oidc.Transactions = (*Store)(nil)
	_ oidc.Accounts     = (*Store)(nil)
)
