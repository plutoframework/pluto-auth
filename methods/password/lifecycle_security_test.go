package password

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
)

func TestChallengesAndGenericRequests(t *testing.T) {
	s, _, sender := testService(t)
	ctx := context.Background()
	now := time.Now().UTC()

	s.config.Clock = func() time.Time { return now }
	for _, request := range []func(context.Context, string) error{s.RequestVerification, s.RequestRecovery} {
		if err := request(ctx, "unknown@example.com"); err != nil {
			t.Fatal(err)
		}
	}

	if len(sender.messages) != 0 {
		t.Fatal("sent to unknown account")
	}

	if err := s.Enroll(ctx, "a@example.com", []byte(oldPassword)); err != nil {
		t.Fatal(err)
	}

	first := sender.last()

	if err := s.RequestRecovery(ctx, "a@example.com"); err != nil {
		t.Fatal(err)
	}

	if len(sender.messages) != 1 {
		t.Fatal("unverified recovery sent")
	}

	if err := s.RequestVerification(ctx, "a@example.com"); err != nil {
		t.Fatal(err)
	}

	second := sender.last()

	if err := s.VerifyEmail(
		ctx,
		first.Token,
	); !errors.Is(
		err,
		ErrInvalidChallenge,
	) {
		t.Fatal("superseded token")
	}

	now = second.ExpiresAt
	if err := s.VerifyEmail(
		ctx,
		second.Token,
	); !errors.Is(
		err,
		ErrInvalidChallenge,
	) {
		t.Fatal("expiry boundary")
	}

	if err := s.RequestVerification(ctx, "a@example.com"); err != nil {
		t.Fatal(err)
	}

	third := sender.last()

	now = third.ExpiresAt.Add(-time.Nanosecond)
	if err := s.VerifyEmail(ctx, third.Token); err != nil {
		t.Fatal(err)
	}

	if err := s.RequestVerification(ctx, "a@example.com"); err != nil {
		t.Fatal(err)
	}

	if sender.last().Token != third.Token {
		t.Fatal("verified resend sent")
	}

	if err := s.RequestRecovery(ctx, "a@example.com"); err != nil {
		t.Fatal(err)
	}

	recovery := sender.last()

	now = recovery.ExpiresAt
	if err := s.ResetPassword(
		ctx,
		recovery.Token,
		[]byte(newPassword),
	); !errors.Is(
		err,
		ErrInvalidChallenge,
	) {
		t.Fatal("reset expiry boundary")
	}

	encoded, _ := json.Marshal(recovery)
	if string(encoded) != "{}" {
		t.Fatal("notification JSON leaked sensitive fields")
	}
}

func TestConcurrentVerificationConsume(t *testing.T) {
	s, store, sender := testService(t)

	ctx := context.Background()
	if err := s.Enroll(ctx, "a@example.com", []byte(oldPassword)); err != nil {
		t.Fatal(err)
	}

	digest, err := ChallengeDigest(VerifyEmail, sender.last().Token)
	if err != nil {
		t.Fatal(err)
	}

	var (
		winners atomic.Int32
		group   sync.WaitGroup
	)
	for range 12 {
		group.Go(func() {
			if err := store.Verify(ctx, digest, time.Now()); err == nil {
				winners.Add(1)
			}
		})
	}

	group.Wait()

	if winners.Load() != 1 {
		t.Fatalf("winners=%d", winners.Load())
	}
}

type createBarrier struct {
	AccountStore
	ready   chan struct{}
	release chan struct{}
}

func (b *createBarrier) Create(
	ctx context.Context,
	d auth.Digest,
	s auth.Session,
) error {
	close(b.ready)
	<-b.release

	return b.AccountStore.Create(ctx, d, s)
}

func TestStaleCredentialIssuanceFence(t *testing.T) {
	for _, mode := range []string{"reset", "disable", "rotation-reset"} {
		t.Run(mode, func(t *testing.T) {
			s, store, sender := testService(t)

			ctx := context.Background()
			if err := s.Enroll(
				ctx,
				"a@example.com",
				[]byte(oldPassword),
			); err != nil {
				t.Fatal(err)
			}

			if err := s.VerifyEmail(ctx, sender.last().Token); err != nil {
				t.Fatal(err)
			}

			existing, err := s.SignIn(ctx, "a@example.com", []byte(oldPassword))
			if err != nil {
				t.Fatal(err)
			}

			if err := s.RequestRecovery(ctx, "a@example.com"); err != nil {
				t.Fatal(err)
			}

			recovery := sender.last()
			b := &createBarrier{
				AccountStore: store,
				ready:        make(chan struct{}),
				release:      make(chan struct{}),
			}

			s.sessions, err = auth.New(b, auth.DefaultConfig())
			if err != nil {
				t.Fatal(err)
			}

			done := make(chan error, 1)

			go func() {
				if mode == "rotation-reset" {
					_, err := s.Sessions().Rotate(ctx, existing.Token)
					done <- err

					return
				}

				_, err := s.SignIn(ctx, "a@example.com", []byte(oldPassword))
				done <- err
			}()
			// Create is reached ONLY after the old password has been verified (or the
			// old versioned session consumed). Commit mutation before allowing issuance.
			select {
			case <-b.ready:
			case <-time.After(5 * time.Second):
				t.Fatal("issuance barrier not reached")
			}

			if mode == "disable" {
				a, _ := store.LookupAccount(ctx, "a@example.com")
				err = s.Disable(ctx, a.ID)
			} else {
				err = s.ResetPassword(ctx, recovery.Token, []byte(newPassword))
			}

			close(b.release)

			if err != nil {
				t.Fatal(err)
			}

			if err := <-done; err == nil {
				t.Fatal("stale credential established session after mutation")
			}

			if _, err := s.Sessions().
				Authenticate(ctx, existing.Token); !errors.Is(
				err,
				auth.ErrUnauthenticated,
			) {
				t.Fatal("old session survived mutation")
			}
		})
	}
}

func TestServiceDependenciesFailClosed(t *testing.T) {
	s, store, sender := testService(t)

	ctx := context.Background()
	if _, err := NewService(
		ctx,
		store,
		s.hasher,
		nil,
		sender,
		auth.DefaultConfig(),
		s.config,
	); !errors.Is(
		err,
		ErrInvalidConfig,
	) {
		t.Fatal("nil limiter")
	}

	if _, err := NewService(
		ctx,
		store,
		s.hasher,
		s.limiter,
		nil,
		auth.DefaultConfig(),
		s.config,
	); !errors.Is(
		err,
		ErrInvalidConfig,
	) {
		t.Fatal("nil sender")
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	if err := s.Enroll(
		cancelled,
		"a@example.com",
		[]byte(oldPassword),
	); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatal("cancelled enrollment", err)
	}

	limiter := s.limiter.(*testLimiter)
	limiter.fail = errors.New("backend unavailable")

	if err := s.Enroll(
		ctx,
		"a@example.com",
		[]byte(oldPassword),
	); !errors.Is(
		err,
		ErrLimited,
	) {
		t.Fatal("limiter failure", err)
	}

	if len(sender.messages) != 0 {
		t.Fatal("limited enrollment mutated")
	}

	limiter.fail = nil
	store.fail = errors.New("storage unavailable")

	if err := s.Enroll(
		ctx,
		"a@example.com",
		[]byte(oldPassword),
	); !errors.Is(
		err,
		ErrUnavailable,
	) {
		t.Fatal("storage failure", err)
	}

	store.fail = nil
	sender.fail = true

	var observed error

	s.config.OnDeliveryError = func(_ context.Context, err error) { observed = err }
	if err := s.Enroll(ctx, "a@example.com", []byte(oldPassword)); err != nil {
		t.Fatal("delivery leaked existence", err)
	}

	if !errors.Is(observed, ErrDelivery) {
		t.Fatal("delivery error unobserved or unredacted")
	}

	if _, err := store.LookupAccount(ctx, "a@example.com"); err != nil {
		t.Fatal("sender ran before commit")
	}

	first := sender.last()
	sender.fail = false

	if err := s.RequestVerification(ctx, "a@example.com"); err != nil {
		t.Fatal(err)
	}

	if err := s.VerifyEmail(
		ctx,
		first.Token,
	); !errors.Is(
		err,
		ErrInvalidChallenge,
	) {
		t.Fatal("failed delivery token still active after resend")
	}

	if err := s.VerifyEmail(ctx, sender.last().Token); err != nil {
		t.Fatal(err)
	}
}

func TestIdentifierAndPolicy(t *testing.T) {
	for _, input := range []string{"A@example.com", "a+b@example.co.uk", "a.b@EXAMPLE.com"} {
		canonical, err := CanonicalEmail(input)
		if err != nil || canonical != strings.ToLower(input) {
			t.Fatal(input, err)
		}
	}

	for _, input := range []string{" a@example.com", "a@example.com ", "a..b@example.com", "a@localhost", "a@-example.com", "a@exam_ple.com", "a@例子.com", "a@b.com@c.com", "\"a\"@example.com", "a\n@example.com"} {
		if _, err := CanonicalEmail(input); !errors.Is(err, ErrInvalidEmail) {
			t.Fatal(input)
		}
	}

	s, _, _ := testService(t)
	for _, value := range []string{strings.Repeat("a", 14), strings.Repeat("界", 14), strings.Repeat("a", 1025), string([]byte{0xff})} {
		if err := s.checkPassword(
			context.Background(),
			[]byte(value),
		); !errors.Is(
			err,
			ErrPasswordPolicy,
		) {
			t.Fatal("policy accepted invalid length")
		}
	}

	for _, value := range []string{strings.Repeat(" ", 15), strings.Repeat("界", 15), strings.Repeat("a", 1024)} {
		if err := s.checkPassword(
			context.Background(),
			[]byte(value),
		); err != nil {
			t.Fatal(err)
		}
	}

	limiter := s.limiter.(*testLimiter)
	_, _ = s.limitEmail(context.Background(), "signin", "A@EXAMPLE.com")
	_, _ = s.limitEmail(context.Background(), "signin", "a@example.com")

	if limiter.keys[0] != limiter.keys[1] ||
		strings.Contains(limiter.keys[0], "example") {
		t.Fatal("inconsistent limiter keys")
	}
}

func TestWindowLimiterBounded(t *testing.T) {
	now := time.Now()

	limiter, err := NewWindowLimiter(
		1,
		2,
		time.Minute,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	for range 2 {
		if err := limiter.Allow(ctx, "a"); err != nil {
			t.Fatal(err)
		}
	}

	if err := limiter.Allow(ctx, "a"); !errors.Is(err, ErrLimited) {
		t.Fatal("limit bypass")
	}

	if err := limiter.Allow(ctx, "b"); !errors.Is(err, ErrLimited) {
		t.Fatal("capacity eviction")
	}

	now = now.Add(time.Minute)

	if err := limiter.Allow(ctx, "b"); err != nil {
		t.Fatal(err)
	}

	if len(limiter.entries) != 1 {
		t.Fatal("unbounded limiter")
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	if err := limiter.Allow(cancelled, "b"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled limiter")
	}
}

func FuzzEmailAndChallenge(f *testing.F) {
	f.Add("A@example.com", "bad-token")
	f.Fuzz(func(t *testing.T, email, token string) {
		if canonical, err := CanonicalEmail(email); err == nil {
			again, err := CanonicalEmail(canonical)
			if err != nil || again != canonical {
				t.Fatal("canonicalization not stable")
			}
		}

		_, _ = ChallengeDigest(VerifyEmail, token)
		_, _ = ChallengeDigest(RecoverPassword, token)
	})
}

type rejectPolicy struct{}

func (rejectPolicy) Check(context.Context, []byte) error {
	return errors.New("blocked or unavailable corpus")
}

func TestInjectedPolicyFailsClosed(t *testing.T) {
	s, _, sender := testService(t)

	s.config.Policy = rejectPolicy{}
	if err := s.Enroll(
		context.Background(),
		"a@example.com",
		[]byte(oldPassword),
	); !errors.Is(
		err,
		ErrPasswordPolicy,
	) {
		t.Fatal("policy bypass", err)
	}

	if len(sender.messages) != 0 {
		t.Fatal("rejected password created account")
	}
}

func TestReplacementPreservesStrongerHashes(t *testing.T) {
	weaker := testHasher(t)

	stronger, err := NewHasher(
		Config{
			MemoryKiB:     32 * 1024,
			Iterations:    3,
			Parallelism:   2,
			MaxConcurrent: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	original, err := stronger.hash(ctx, []byte(oldPassword), 32, 64)
	if err != nil {
		t.Fatal(err)
	}

	replacement, err := weaker.HashAtLeast(ctx, []byte(newPassword), original)
	if err != nil {
		t.Fatal(err)
	}

	before, err := parse(original)
	if err != nil {
		t.Fatal(err)
	}

	after, err := parse(replacement)
	if err != nil {
		t.Fatal(err)
	}

	if after.memory < before.memory || after.iterations < before.iterations ||
		after.parallel < before.parallel || len(after.salt) < len(before.salt) ||
		len(after.key) < len(before.key) {
		t.Fatal("credential replacement downgraded hash")
	}

	if valid, err := weaker.Verify(
		ctx,
		[]byte(newPassword),
		replacement,
	); err != nil ||
		!valid {
		t.Fatal("replacement not verifiable", err)
	}
}

func TestChallengePurposeSeparation(t *testing.T) {
	token, _, err := newChallenge(VerifyEmail, DefaultLifecycleConfig())
	if err != nil {
		t.Fatal(err)
	}

	verification, err := ChallengeDigest(VerifyEmail, token)
	if err != nil {
		t.Fatal(err)
	}

	recovery, err := ChallengeDigest(RecoverPassword, token)
	if err != nil {
		t.Fatal(err)
	}

	if verification == recovery {
		t.Fatal("challenge purposes share digest namespace")
	}

	if _, err := ChallengeDigest(
		Purpose("unknown"),
		token,
	); !errors.Is(
		err,
		ErrInvalidChallenge,
	) {
		t.Fatal("unsupported purpose")
	}
}

type cancelAfterEnrollment struct {
	AccountStore
	cancel context.CancelFunc
}

func (s cancelAfterEnrollment) Enroll(
	ctx context.Context,
	a Account,
	c Challenge,
) error {
	if err := s.AccountStore.Enroll(ctx, a, c); err != nil {
		return err
	}

	s.cancel()

	return nil
}

type cancelledSender struct{ called bool }

func (s *cancelledSender) Send(ctx context.Context, _ Notification) error {
	s.called = true
	return ctx.Err()
}

func TestCancelledPostCommitDelivery(t *testing.T) {
	s, store, _ := testService(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.store = cancelAfterEnrollment{AccountStore: store, cancel: cancel}
	sender := &cancelledSender{}
	s.sender = sender

	var observed error

	s.config.OnDeliveryError = func(_ context.Context, err error) { observed = err }
	if err := s.Enroll(ctx, "a@example.com", []byte(oldPassword)); err != nil {
		t.Fatal("post-commit cancellation changed acceptance", err)
	}

	if !sender.called || observed != ErrDelivery {
		t.Fatal("cancelled sender failure not observed safely")
	}

	if _, err := store.LookupAccount(
		context.Background(),
		"a@example.com",
	); err != nil {
		t.Fatal("post-commit delivery cancellation lost enrollment", err)
	}
}
