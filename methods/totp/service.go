package totp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	auth "github.com/plutoframework/pluto-auth"
)

type Service struct {
	store     Store
	protector Protector
	limiter   Limiter
	config    Config
	sessions  *auth.Manager
}

func New(
	store Store,
	protector Protector,
	limiter Limiter,
	config Config,
) (*Service, error) {
	if store == nil || protector == nil || limiter == nil ||
		config.Issuer == "" ||
		len(config.Issuer) > 128 ||
		strings.ContainsAny(config.Issuer, ":\x00\r\n") {
		return nil, ErrConfig
	}

	manager, err := auth.New(store, config.Sessions)
	if err != nil {
		return nil, ErrConfig
	}

	return &Service{
		store:     store,
		protector: protector,
		limiter:   limiter,
		config:    config,
		sessions:  manager,
	}, nil
}

// Sessions provides the same account-fenced manager for HTTP authentication.
// Start methods remain trusted primitives, never unauthenticated endpoints.
func (s *Service) Sessions() *auth.Manager { return s.sessions }

// Browser generates an independent browser-binding secret. HTTP hosts must keep
// it in a Secure, HttpOnly, SameSite cookie, not in the challenge response/body.
func Browser() string { return random(32) }

func random(n int) string {
	value := make([]byte, n)
	_, _ = rand.Read(value)

	return base64.RawURLEncoding.EncodeToString(value)
}

func digest(purpose, value string) auth.Digest {
	return sha256.Sum256([]byte("pluto-auth/totp/" + purpose + "\x00" + value))
}

func secret(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)

	return err == nil && len(decoded) == 32 &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

// Begin accepts ONLY a server-local ceremony from a verified primary method,
// e.g. password.Service.BeginSignIn. Never construct it from request evidence.
// Every management action requires primary proof no older than five minutes.
// label is a host-selected display label, not an authority or lookup identifier.
func (s *Service) Begin(
	ctx context.Context,
	ceremony auth.Ceremony,
	browser string,
	action Action,
	label string,
) (Setup, error) {
	now := s.config.Sessions.Clock().UTC()

	account := ceremony.Account()
	if !secret(browser) || account.SubjectID == "" || account.Disabled ||
		(ceremony.Stage() != auth.AwaitingFactor && ceremony.Stage() != auth.Authenticated) {
		return Setup{}, ErrDenied
	}

	// Extract verified primary metadata without manufacturing factor evidence.
	primary, at, expires := ceremony.PrimaryEvidence()
	if at.IsZero() || now.Before(at) || !now.Before(at.Add(5*time.Minute)) ||
		!now.Before(expires) {
		return Setup{}, ErrDenied
	}

	if expires.After(at.Add(5 * time.Minute)) {
		expires = at.Add(5 * time.Minute)
	}

	if err := s.allow(ctx, account.SubjectID); err != nil {
		return Setup{}, err
	}

	factor, err := s.store.Factor(ctx, account.SubjectID)
	if err != nil && !errors.Is(err, auth.ErrNotFound) {
		return Setup{}, ErrUnavailable
	}

	exists := factor.Generation != ""

	switch action {
	case SignIn:
		if ceremony.Stage() != auth.AwaitingFactor || !exists {
			return Setup{}, ErrDenied
		}
	case Enroll:
		if exists || account.SecondFactorRequired {
			return Setup{}, ErrDenied
		}
	case Replace, Remove, Regenerate:
		if !exists {
			return Setup{}, ErrDenied
		}
	default:
		return Setup{}, ErrDenied
	}

	token := random(32)
	pending := Pending{
		Digest: digest(
			"challenge",
			token,
		),
		Browser:   digest("browser", browser),
		Account:   account,
		Action:    action,
		Primary:   primary,
		PrimaryAt: at,
		Expires:   expires,
	}
	result := Setup{Challenge: token, Expires: expires}

	if action == Enroll || action == Replace {
		if len(label) == 0 || len(label) > 256 ||
			strings.ContainsAny(label, "\x00\r\n") {
			return Setup{}, ErrDenied
		}

		seed := make([]byte, 20)
		_, _ = rand.Read(seed)

		encrypted, err := s.protector.Seal(ctx, account.SubjectID, seed)
		if err != nil || len(encrypted) == 0 {
			return Setup{}, ErrUnavailable
		}

		pending.Candidate = Factor{
			Generation:    random(32),
			EncryptedSeed: encrypted,
			LastStep:      -1,
		}
		result.URI = provisioning(seed, s.config.Issuer, label)
	}

	if err := s.store.Save(ctx, pending); err != nil {
		return Setup{}, denied(err)
	}

	return result, nil
}

// Finish verifies code (TOTP or recovery) and, for enrollment/replacement, the
// new seed's confirmation code. Recovery is an explicit mode, never a fallback
// on TOTP failure. Fresh primary proof is always required, including recovery.
func (s *Service) Finish(
	ctx context.Context,
	challenge, browser, code string,
	recovery bool,
	confirmation string,
) (Result, error) {
	if !secret(challenge) || !secret(browser) {
		return Result{}, ErrDenied
	}

	now := s.config.Sessions.Clock().UTC()

	pending, err := s.store.Load(
		ctx,
		digest("challenge", challenge),
		digest("browser", browser),
		now,
	)
	if err != nil {
		return Result{}, denied(err)
	}

	// Shared per-account limits prevent rotating challenges/browser identities
	// from multiplying the OTP guessing budget. The host also limits ingress.
	if err := s.allow(ctx, pending.Account.SubjectID); err != nil {
		return Result{}, err
	}

	factor, err := s.store.Factor(ctx, pending.Account.SubjectID)
	if err != nil &&
		(pending.Action != Enroll || !errors.Is(err, auth.ErrNotFound)) {
		return Result{}, denied(err)
	}

	command := Commit{
		Pending:            pending,
		ExpectedGeneration: factor.Generation,
		Step:               -1,
		NewStep:            -1,
	}
	method := auth.MethodTOTP

	if pending.Action != Enroll {
		if recovery {
			if !secret(code) {
				return Result{}, ErrDenied
			}

			command.Recovery = digest(
				"recovery/"+pending.Account.SubjectID,
				code,
			)
			method = auth.MethodRecoveryCode
		} else {
			seed, err := s.protector.Open(
				ctx,
				pending.Account.SubjectID,
				factor.EncryptedSeed,
			)
			if err != nil {
				return Result{}, ErrUnavailable
			}

			step, ok := Match(seed, code, now, factor.LastStep)
			if !ok {
				return Result{}, ErrDenied
			}

			command.Step = step
		}
	}

	if pending.Action == Enroll || pending.Action == Replace {
		seed, err := s.protector.Open(
			ctx,
			pending.Account.SubjectID,
			pending.Candidate.EncryptedSeed,
		)
		if err != nil {
			return Result{}, ErrUnavailable
		}

		step, ok := Match(seed, confirmation, now, -1)
		if !ok {
			return Result{}, ErrDenied
		}

		command.NewStep = step
	}

	var result Result

	if pending.Action == Enroll || pending.Action == Replace ||
		pending.Action == Regenerate {
		for range 10 {
			value := random(32)
			result.RecoveryCodes = append(result.RecoveryCodes, value)
			command.RecoveryDigests = append(
				command.RecoveryDigests,
				digest("recovery/"+pending.Account.SubjectID, value),
			)
		}
	}

	if pending.Action == SignIn {
		ceremony, err := auth.NewCeremony(
			pending.Account,
			true,
			pending.PrimaryAt,
			pending.Expires.Sub(pending.PrimaryAt),
		)
		if err != nil {
			return Result{}, ErrDenied
		}

		ceremony, err = ceremony.PrimaryVerified(
			pending.Primary,
			pending.PrimaryAt,
		)
		if err != nil {
			return Result{}, ErrDenied
		}

		ceremony, err = ceremony.SecondFactorVerified(method, now)
		if err != nil {
			return Result{}, ErrDenied
		}

		proof, err := ceremony.Complete(now)
		if err != nil {
			return Result{}, ErrDenied
		}

		// The manager generates the session token; the scoped adapter persists it
		// only through the same atomic commit that consumes the second-factor proof.
		scoped := &commitStore{Store: s.store, command: command}

		manager, err := auth.New(scoped, s.config.Sessions)
		if err != nil {
			return Result{}, ErrConfig
		}

		issued, err := manager.StartAuthenticated(ctx, proof)
		if err != nil {
			return Result{}, denied(err)
		}

		result.Issued = issued
	} else {
		if err := s.store.Commit(ctx, command); err != nil {
			return Result{}, denied(err)
		}

		if s.config.Changed != nil {
			s.config.Changed(ctx, pending.Account.SubjectID, pending.Action)
		}
	}

	return result, nil
}

type commitStore struct {
	Store
	command Commit
}

func (s *commitStore) CreateAuthenticated(
	ctx context.Context,
	digest auth.Digest,
	session auth.Session,
) error {
	command := s.command
	command.Session = session
	command.SessionDigest = digest

	return s.Commit(ctx, command)
}

func (s *Service) allow(ctx context.Context, subject string) error {
	key := digest("attempt", subject)
	if err := s.limiter.Allow(ctx, hex.EncodeToString(key[:])); err != nil {
		return ErrLimited
	}

	return ctx.Err()
}

func denied(err error) error {
	if errors.Is(err, auth.ErrNotFound) ||
		errors.Is(err, auth.ErrUnauthenticated) ||
		errors.Is(err, ErrDenied) ||
		errors.Is(err, auth.ErrAuthenticationRequired) {
		return ErrDenied
	}

	return ErrUnavailable
}
