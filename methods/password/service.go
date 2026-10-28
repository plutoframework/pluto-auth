package password

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	auth "github.com/plutoframework/pluto-auth"
)

// Service owns only the local password lifecycle. Its manager is constructed
// internally from the SAME account/session store so callers cannot accidentally
// pair credential fencing with a different session backend.
type Service struct {
	store    AccountStore
	hasher   *Hasher
	sessions *auth.Manager
	limiter  AttemptLimiter
	sender   Sender
	config   LifecycleConfig
	dummy    string
}

func NewService(ctx context.Context, store AccountStore, hasher *Hasher,
	limiter AttemptLimiter, sender Sender, sessions auth.Config,
	config LifecycleConfig,
) (*Service, error) {
	if store == nil || hasher == nil || limiter == nil || sender == nil ||
		config.Clock == nil || config.VerificationTTL <= 0 ||
		config.VerificationTTL > 48*time.Hour || config.RecoveryTTL <= 0 ||
		config.RecoveryTTL > time.Hour {
		return nil, ErrInvalidConfig
	}

	manager, err := auth.New(store, sessions)
	if err != nil {
		return nil, err
	}

	dummy, err := hasher.Hash(ctx, []byte("pluto-dummy-account-verification"))
	if err != nil {
		return nil, err
	}

	return &Service{
		store: store, hasher: hasher, sessions: manager,
		limiter: limiter, sender: sender, config: config, dummy: dummy,
	}, nil
}

// Sessions supplies authentication/revocation to httpauth. Do not use Start as
// a login endpoint; this service uses versioned issuance after verification.
func (s *Service) Sessions() *auth.Manager { return s.sessions }

// Enroll returns no identity or challenge. Duplicate enrollment is accepted
// without altering the existing password or sending an additional message.
func (s *Service) Enroll(
	ctx context.Context,
	email string,
	value []byte,
) error {
	email, err := s.limitEmail(ctx, "enroll", email)
	if err != nil {
		return err
	}

	if err := s.checkPassword(ctx, value); err != nil {
		return err
	}

	hash, err := s.hasher.Hash(ctx, value)
	if err != nil {
		return ErrUnavailable
	}

	token, challenge, err := newChallenge(VerifyEmail, s.config)
	if err != nil {
		return ErrUnavailable
	}

	account := Account{ID: rand.Text(), Email: email, Hash: hash, Version: 1}
	if err := s.store.Enroll(ctx, account, challenge); err != nil {
		if errors.Is(err, ErrConflict) {
			return nil
		}

		return ErrUnavailable
	}

	s.deliver(ctx, account, token, challenge)

	return nil
}

func (s *Service) RequestVerification(ctx context.Context, email string) error {
	return s.request(ctx, email, VerifyEmail)
}

func (s *Service) RequestRecovery(ctx context.Context, email string) error {
	return s.request(ctx, email, RecoverPassword)
}

func (s *Service) request(
	ctx context.Context,
	email string,
	purpose Purpose,
) error {
	email, err := s.limitEmail(ctx, string(purpose), email)
	if err != nil {
		return err
	}

	token, challenge, err := newChallenge(purpose, s.config)
	if err != nil {
		return ErrUnavailable
	}

	account, err := s.store.ReplaceChallenge(ctx, email, challenge)
	if errors.Is(err, auth.ErrNotFound) {
		return nil
	}

	if err != nil {
		return ErrUnavailable
	}

	s.deliver(ctx, account, token, challenge)

	return nil
}

func (s *Service) deliver(ctx context.Context, account Account,
	token string, challenge Challenge,
) {
	if err := s.sender.Send(ctx, Notification{
		Email:     account.Email,
		Purpose:   challenge.Purpose,
		Token:     token,
		ExpiresAt: challenge.ExpiresAt,
	}); err != nil && s.config.OnDeliveryError != nil {
		s.config.OnDeliveryError(ctx, ErrDelivery)
	}
}

func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	digest, err := s.limitChallenge(ctx, VerifyEmail, token)
	if err != nil {
		return err
	}

	err = s.store.Verify(ctx, digest, s.config.Clock().UTC())

	return challengeError(err)
}

func (s *Service) ResetPassword(
	ctx context.Context,
	token string,
	value []byte,
) error {
	digest, err := s.limitChallenge(ctx, RecoverPassword, token)
	if err != nil {
		return err
	}

	if err := s.checkPassword(ctx, value); err != nil {
		return err
	}

	account, err := s.store.ChallengeAccount(ctx, RecoverPassword, digest,
		s.config.Clock().UTC())
	if err != nil {
		return challengeError(err)
	}

	// Preserve each stored cost dimension; reset must not downgrade a stronger
	// stored hash just because the service's defaults have changed.
	hash, err := s.hasher.HashAtLeast(ctx, value, account.Hash)
	if err != nil {
		return ErrUnavailable
	}

	return challengeError(s.store.Reset(ctx, digest, account.Version, hash,
		s.config.Clock().UTC()))
}

func (s *Service) SignIn(ctx context.Context, email string,
	value []byte,
) (auth.IssuedSession, error) {
	email, err := s.limitEmail(ctx, "signin", email)
	if err != nil {
		if errors.Is(err, ErrInvalidEmail) {
			err = ErrInvalidCredentials
		}

		return auth.IssuedSession{}, err
	}

	if len(value) == 0 || len(value) > MaxPasswordBytes {
		return auth.IssuedSession{}, ErrInvalidCredentials
	}

	account, lookupErr := s.store.LookupAccount(ctx, email)
	if lookupErr != nil && !errors.Is(lookupErr, auth.ErrNotFound) {
		return auth.IssuedSession{}, ErrUnavailable
	}

	encoded := account.Hash
	if lookupErr != nil {
		encoded = s.dummy
	}

	valid, err := s.hasher.Verify(ctx, value, encoded)
	if err != nil {
		return auth.IssuedSession{}, ErrUnavailable
	}

	if !valid || lookupErr != nil || !account.Verified || account.Disabled {
		return auth.IssuedSession{}, ErrInvalidCredentials
	}

	issued, err := s.sessions.StartVersioned(ctx, account.ID, account.Version)
	if errors.Is(err, auth.ErrUnauthenticated) {
		return auth.IssuedSession{}, ErrInvalidCredentials
	}

	if err != nil {
		return auth.IssuedSession{}, ErrUnavailable
	}

	return issued, nil
}

// Disable is for trusted application code after its own authorization check.
func (s *Service) Disable(ctx context.Context, subject string) error {
	return s.store.Disable(ctx, subject)
}

func (s *Service) limitEmail(
	ctx context.Context,
	op, email string,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	canonical, err := CanonicalEmail(email)
	if err != nil {
		return "", err
	}

	if err := s.allow(ctx, op, canonical); err != nil {
		return "", err
	}

	return canonical, nil
}

func (s *Service) limitChallenge(ctx context.Context, purpose Purpose,
	token string,
) (auth.Digest, error) {
	if err := ctx.Err(); err != nil {
		return auth.Digest{}, err
	}

	digest, err := ChallengeDigest(purpose, token)
	if err != nil {
		return auth.Digest{}, err
	}

	if err := s.allow(ctx, "consume_"+string(purpose), token); err != nil {
		return auth.Digest{}, err
	}

	return digest, nil
}

func (s *Service) allow(ctx context.Context, op, identifier string) error {
	key := sha256.Sum256([]byte(op + "\x00" + identifier))
	if err := s.limiter.Allow(ctx, hex.EncodeToString(key[:])); err != nil {
		return ErrLimited
	}

	return ctx.Err()
}

func challengeError(err error) error {
	if errors.Is(err, auth.ErrNotFound) || errors.Is(err, ErrInvalidChallenge) {
		return ErrInvalidChallenge
	}

	if err != nil {
		return ErrUnavailable
	}

	return nil
}
