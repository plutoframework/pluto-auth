package postgres_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/methods/password"
	"github.com/plutoframework/pluto-auth/stores/postgres"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	enrollmentPassword  = "correct horse Unicode 密碼"
	replacementPassword = "a different long password 密碼"
)

type localSender struct {
	mu       sync.Mutex
	messages []password.Notification
	pool     *pgxpool.Pool
	t        *testing.T
}

func (s *localSender) Send(ctx context.Context, n password.Notification) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var count int
	if err := s.pool.QueryRow(ctx,
		"SELECT count(*) FROM pluto_auth_challenges WHERE purpose = $1",
		string(n.Purpose)).Scan(&count); err != nil || count == 0 {
		s.t.Error("notification before committed challenge")
	}

	s.messages = append(s.messages, n)

	return nil
}

func (s *localSender) last() password.Notification {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.messages[len(s.messages)-1]
}

func localSetup(
	t *testing.T,
) (*password.Service, *postgres.LocalStore, *localSender, *pgxpool.Pool) {
	t.Helper()

	pool := testPool(t)

	ctx := context.Background()
	if _, err := pool.Exec(ctx, postgres.LocalSchema); err != nil {
		t.Fatal(err)
	}

	store, err := postgres.NewLocal(pool)
	if err != nil {
		t.Fatal(err)
	}

	hasher, err := password.NewHasher(password.Config{
		MemoryKiB:  19 * 1024,
		Iterations: 2, Parallelism: 1, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	limiter, err := password.NewWindowLimiter(1000, 100, time.Minute, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	sender := &localSender{pool: pool, t: t}

	service, err := password.NewService(ctx, store, hasher, limiter, sender,
		auth.DefaultConfig(), password.DefaultLifecycleConfig())
	if err != nil {
		t.Fatal(err)
	}

	return service, store, sender, pool
}

func enrollVerified(t *testing.T, s *password.Service, sender *localSender) {
	t.Helper()

	ctx := context.Background()
	if err := s.Enroll(
		ctx,
		"Alice@Example.com",
		[]byte(enrollmentPassword),
	); err != nil {
		t.Fatal(err)
	}

	if err := s.VerifyEmail(ctx, sender.last().Token); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresLocalLifecycle(t *testing.T) {
	s, store, sender, pool := localSetup(t)

	ctx := context.Background()
	if err := s.Enroll(
		ctx,
		"Alice@Example.COM",
		[]byte(enrollmentPassword),
	); err != nil {
		t.Fatal(err)
	}

	verification := sender.last()

	if _, err := s.SignIn(
		ctx,
		"alice@example.com",
		[]byte(enrollmentPassword),
	); !errors.Is(
		err,
		password.ErrInvalidCredentials,
	) {
		t.Fatal("unverified signin", err)
	}

	if err := s.Enroll(
		ctx,
		"alice@example.com",
		[]byte(replacementPassword),
	); err != nil {
		t.Fatal("duplicate response", err)
	}

	if len(sender.messages) != 1 {
		t.Fatal("duplicate notification")
	}

	if err := s.RequestVerification(ctx, "alice@example.com"); err != nil {
		t.Fatal(err)
	}

	if err := s.VerifyEmail(
		ctx,
		verification.Token,
	); !errors.Is(
		err,
		password.ErrInvalidChallenge,
	) {
		t.Fatal("superseded challenge", err)
	}

	current := sender.last()
	digest, _ := password.ChallengeDigest(password.VerifyEmail, current.Token)

	var stored []byte
	if err := pool.QueryRow(ctx, "SELECT token_digest FROM pluto_auth_challenges").
		Scan(&stored); err != nil ||
		string(stored) != string(digest[:]) {
		t.Fatal("challenge not hashed at rest")
	}

	if err := s.VerifyEmail(ctx, current.Token); err != nil {
		t.Fatal(err)
	}

	issued, err := s.SignIn(
		ctx,
		"ALICE@example.com",
		[]byte(enrollmentPassword),
	)
	if err != nil {
		t.Fatal(err)
	}

	rotated, err := s.Sessions().Rotate(ctx, issued.Token)
	if err != nil || rotated.Session.CredentialVersion != 1 {
		t.Fatal("rotation fence", err)
	}

	if _, err := s.Sessions().
		Start(ctx, rotated.Session.SubjectID); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatal("unfenced issuance", err)
	}

	if err := s.RequestRecovery(ctx, "alice@example.com"); err != nil {
		t.Fatal(err)
	}

	recovery := sender.last()
	if err := s.VerifyEmail(
		ctx,
		recovery.Token,
	); !errors.Is(
		err,
		password.ErrInvalidChallenge,
	) {
		t.Fatal("wrong purpose")
	}

	if err := s.ResetPassword(
		ctx,
		recovery.Token,
		[]byte(replacementPassword),
	); err != nil {
		t.Fatal(err)
	}

	if err := s.ResetPassword(
		ctx,
		recovery.Token,
		[]byte(replacementPassword),
	); !errors.Is(
		err,
		password.ErrInvalidChallenge,
	) {
		t.Fatal("replay")
	}

	var remaining int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM pluto_auth_sessions").
		Scan(&remaining); err != nil ||
		remaining != 0 {
		t.Fatal("reset did not delete sessions", err)
	}

	if _, err := s.Sessions().
		Authenticate(ctx, rotated.Token); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatal("revocation", err)
	}

	if _, err := s.SignIn(
		ctx,
		"alice@example.com",
		[]byte(enrollmentPassword),
	); !errors.Is(
		err,
		password.ErrInvalidCredentials,
	) {
		t.Fatal("old hash accepted")
	}

	fresh, err := s.SignIn(
		ctx,
		"alice@example.com",
		[]byte(replacementPassword),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Disable(ctx, fresh.Session.SubjectID); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Sessions().
		Authenticate(ctx, fresh.Token); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatal("disabled session")
	}

	if _, err := s.SignIn(
		ctx,
		"alice@example.com",
		[]byte(replacementPassword),
	); !errors.Is(
		err,
		password.ErrInvalidCredentials,
	) {
		t.Fatal("disabled signin")
	}

	for _, request := range []func(context.Context, string) error{s.RequestVerification, s.RequestRecovery} {
		for _, email := range []string{"unknown@example.com", "alice@example.com"} {
			if err := request(ctx, email); err != nil {
				t.Fatal("generic request", err)
			}
		}
	}

	if _, err := store.PruneExpiredChallenges(
		ctx,
		time.Now().Add(48*time.Hour),
	); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresLocalAtomicConsume(t *testing.T) {
	s, store, sender, _ := localSetup(t)

	ctx := context.Background()
	if err := s.Enroll(
		ctx,
		"alice@example.com",
		[]byte(enrollmentPassword),
	); err != nil {
		t.Fatal(err)
	}

	digest, _ := password.ChallengeDigest(
		password.VerifyEmail,
		sender.last().Token,
	)

	var (
		winners atomic.Int32
		group   sync.WaitGroup
	)
	for range 16 {
		group.Go(func() {
			err := store.Verify(ctx, digest, time.Now())
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, auth.ErrNotFound) {
				t.Error(err)
			}
		})
	}

	group.Wait()

	if winners.Load() != 1 {
		t.Fatalf("verification winners=%d", winners.Load())
	}

	if err := s.RequestRecovery(ctx, "alice@example.com"); err != nil {
		t.Fatal(err)
	}

	recovery := sender.last()
	digest, _ = password.ChallengeDigest(
		password.RecoverPassword,
		recovery.Token,
	)

	a, err := store.LookupAccount(ctx, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}

	winners.Store(0)

	for range 16 {
		group.Go(func() {
			err := store.Reset(ctx, digest, a.Version, a.Hash, time.Now())
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, auth.ErrNotFound) {
				t.Error(err)
			}
		})
	}

	group.Wait()

	if winners.Load() != 1 {
		t.Fatalf("reset winners=%d", winners.Load())
	}
}

func TestPostgresLocalTransactionRollback(t *testing.T) {
	s, store, sender, pool := localSetup(t)
	ctx := context.Background()
	now := time.Now().UTC()
	// The second insert fails; the first insert must not leave an account.
	err := store.Enroll(ctx, password.Account{
		ID: "rollback-account", Email: "rollback@example.com",
		Hash: "not-used", Version: 1,
	}, password.Challenge{
		Purpose:   password.VerifyEmail,
		CreatedAt: now, ExpiresAt: now,
	})
	if err == nil {
		t.Fatal("accepted invalid challenge")
	}

	if _, err := store.LookupAccount(
		ctx,
		"rollback@example.com",
	); !errors.Is(
		err,
		auth.ErrNotFound,
	) {
		t.Fatal("partial enrollment", err)
	}

	if err := s.Enroll(
		ctx,
		"alice@example.com",
		[]byte(enrollmentPassword),
	); err != nil {
		t.Fatal(err)
	}

	token := sender.last().Token

	installFailure(t, pool, "pluto_auth_challenges")

	if err := s.VerifyEmail(
		ctx,
		token,
	); !errors.Is(
		err,
		password.ErrUnavailable,
	) {
		t.Fatal("expected verification rollback", err)
	}

	a, err := store.LookupAccount(ctx, "alice@example.com")
	if err != nil || a.Verified {
		t.Fatal("partial verification")
	}

	removeFailure(t, pool, "pluto_auth_challenges")

	if err := s.VerifyEmail(ctx, token); err != nil {
		t.Fatal("rolled-back token was consumed", err)
	}

	issued, err := s.SignIn(
		ctx,
		"alice@example.com",
		[]byte(enrollmentPassword),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.RequestRecovery(ctx, "alice@example.com"); err != nil {
		t.Fatal(err)
	}

	recovery := sender.last()

	installFailure(t, pool, "pluto_auth_sessions")

	if err := s.ResetPassword(
		ctx,
		recovery.Token,
		[]byte(replacementPassword),
	); !errors.Is(
		err,
		password.ErrUnavailable,
	) {
		t.Fatal("expected reset rollback", err)
	}

	a, err = store.LookupAccount(ctx, "alice@example.com")
	if err != nil || a.Version != 1 {
		t.Fatal("partial credential update")
	}

	if _, err := s.Sessions().Authenticate(ctx, issued.Token); err != nil {
		t.Fatal("rollback lost session", err)
	}

	if err := s.Disable(ctx, a.ID); err == nil {
		t.Fatal("disable committed despite revocation failure")
	}

	a, err = store.LookupAccount(ctx, "alice@example.com")
	if err != nil || a.Disabled || a.Version != 1 {
		t.Fatal("partial disable")
	}

	removeFailure(t, pool, "pluto_auth_sessions")

	if err := s.ResetPassword(
		ctx,
		recovery.Token,
		[]byte(replacementPassword),
	); err != nil {
		t.Fatal("rollback consumed recovery", err)
	}

	if _, err := s.Sessions().
		Authenticate(ctx, issued.Token); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatal("commit did not revoke")
	}
}

func installFailure(t *testing.T, pool *pgxpool.Pool, table string) {
	t.Helper()

	// Only fixed table names supplied by these tests, never application input.
	_, err := pool.Exec(context.Background(), `
 CREATE OR REPLACE FUNCTION fail_auth_delete() RETURNS trigger
 LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected test failure'; END $$;
 CREATE TRIGGER fail_delete BEFORE DELETE ON `+table+`
 FOR EACH ROW EXECUTE FUNCTION fail_auth_delete();`)
	if err != nil {
		t.Fatal(err)
	}
}

func removeFailure(t *testing.T, pool *pgxpool.Pool, table string) {
	t.Helper()

	if _, err := pool.Exec(
		context.Background(),
		"DROP TRIGGER fail_delete ON "+table,
	); err != nil {
		t.Fatal(err)
	}
}

type postgresCreateBarrier struct {
	password.AccountStore
	ready   chan struct{}
	release chan struct{}
}

func (b *postgresCreateBarrier) Create(ctx context.Context, d auth.Digest,
	session auth.Session,
) error {
	close(b.ready)
	<-b.release

	return b.AccountStore.Create(ctx, d, session)
}

func TestPostgresStaleSignInFence(t *testing.T) {
	for _, operation := range []string{"reset", "disable"} {
		t.Run(operation, func(t *testing.T) {
			original, store, sender, _ := localSetup(t)
			enrollVerified(t, original, sender)

			ctx := context.Background()
			if err := original.RequestRecovery(
				ctx,
				"alice@example.com",
			); err != nil {
				t.Fatal(err)
			}

			recovery := sender.last()
			barrier := &postgresCreateBarrier{
				AccountStore: store,
				ready:        make(chan struct{}),
				release:      make(chan struct{}),
			}

			hasher, err := password.NewHasher(password.DefaultConfig())
			if err != nil {
				t.Fatal(err)
			}

			limiter, err := password.NewWindowLimiter(
				100,
				20,
				time.Minute,
				time.Now,
			)
			if err != nil {
				t.Fatal(err)
			}

			stale, err := password.NewService(
				ctx,
				barrier,
				hasher,
				limiter,
				sender,
				auth.DefaultConfig(),
				password.DefaultLifecycleConfig(),
			)
			if err != nil {
				t.Fatal(err)
			}

			done := make(chan error, 1)

			go func() {
				_, err := stale.SignIn(
					ctx,
					"alice@example.com",
					[]byte(enrollmentPassword),
				)
				done <- err
			}()
			// Reaching Create proves verification of the OLD hash has completed.
			select {
			case <-barrier.ready:
			case <-time.After(5 * time.Second):
				t.Fatal("sign-in did not reach issuance fence")
			}

			if operation == "reset" {
				err = original.ResetPassword(
					ctx,
					recovery.Token,
					[]byte(replacementPassword),
				)
			} else {
				a, _ := store.LookupAccount(ctx, "alice@example.com")
				err = original.Disable(ctx, a.ID)
			}

			close(barrier.release)

			if err != nil {
				t.Fatal(err)
			}

			if err := <-done; !errors.Is(err, password.ErrInvalidCredentials) {
				t.Fatal("stale sign-in escaped mutation", err)
			}
		})
	}
}

func TestPostgresChallengeExpiry(t *testing.T) {
	s, store, sender, _ := localSetup(t)

	ctx := context.Background()
	if err := s.Enroll(
		ctx,
		"alice@example.com",
		[]byte(enrollmentPassword),
	); err != nil {
		t.Fatal(err)
	}

	n := sender.last()
	digest, _ := password.ChallengeDigest(password.VerifyEmail, n.Token)

	expiry := n.ExpiresAt.Truncate(time.Microsecond)
	if err := store.Verify(
		ctx,
		digest,
		expiry,
	); !errors.Is(
		err,
		auth.ErrNotFound,
	) {
		t.Fatal("boundary accepted", err)
	}

	if err := store.Verify(
		ctx,
		digest,
		expiry.Add(-time.Microsecond),
	); err != nil {
		t.Fatal(err)
	}
}

type cancelledCommitDB struct {
	*pgxpool.Pool
	cancel context.CancelFunc
}

func (d cancelledCommitDB) BeginTx(
	ctx context.Context,
	options pgx.TxOptions,
) (pgx.Tx, error) {
	tx, err := d.Pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}

	return cancelledCommitTx{Tx: tx, cancel: d.cancel}, nil
}

type cancelledCommitTx struct {
	pgx.Tx
	cancel context.CancelFunc
}

func (t cancelledCommitTx) Commit(ctx context.Context) error {
	t.cancel()

	return t.Tx.Commit(ctx)
}

func TestPostgresResetCancelledCommit(t *testing.T) {
	s, store, sender, pool := localSetup(t)
	enrollVerified(t, s, sender)

	ctx := context.Background()
	if err := s.RequestRecovery(ctx, "alice@example.com"); err != nil {
		t.Fatal(err)
	}

	recovery := sender.last()
	digest, _ := password.ChallengeDigest(
		password.RecoverPassword,
		recovery.Token,
	)

	a, err := store.LookupAccount(ctx, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	defer cancel()

	failing, err := postgres.NewLocal(
		cancelledCommitDB{Pool: pool, cancel: cancel},
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := failing.Reset(
		cancelled,
		digest,
		a.Version,
		a.Hash,
		time.Now(),
	); err == nil {
		t.Fatal("cancelled commit accepted")
	}

	unchanged, err := store.LookupAccount(ctx, "alice@example.com")
	if err != nil || unchanged.Version != a.Version ||
		unchanged.Hash != a.Hash {
		t.Fatal("cancelled reset changed credentials", err)
	}

	if _, err := store.ChallengeAccount(
		ctx,
		password.RecoverPassword,
		digest,
		time.Now(),
	); err != nil {
		t.Fatal("cancelled reset consumed token", err)
	}
}

func TestPostgresConcurrentEnrollmentUniqueness(t *testing.T) {
	s, _, sender, pool := localSetup(t)
	ctx := context.Background()

	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if err := s.Enroll(
				ctx,
				"ALICE@example.com",
				[]byte(enrollmentPassword),
			); err != nil {
				t.Error(err)
			}
		})
	}

	group.Wait()

	var accounts, challenges int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM pluto_auth_accounts").
		Scan(&accounts); err != nil {
		t.Fatal(err)
	}

	if err := pool.QueryRow(ctx, "SELECT count(*) FROM pluto_auth_challenges").
		Scan(&challenges); err != nil {
		t.Fatal(err)
	}

	if accounts != 1 || challenges != 1 || len(sender.messages) != 1 {
		t.Fatal(
			"duplicate enrollment left multiple accounts/challenges/notifications",
		)
	}
}
