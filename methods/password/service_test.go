package password

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

// Test-only account store. Its account mutex serializes issuance with mutation.
// PostgreSQL tests exercise the actual production transaction implementation.
type accountMemory struct {
	auth.SessionStore
	mu         sync.Mutex
	accounts   map[string]Account
	challenges map[auth.Digest]memoryChallenge
	fail       error
	creates    int
}

type memoryChallenge struct {
	Challenge
	account string
	version int64
}

func newAccountMemory(t *testing.T) *accountMemory {
	t.Helper()

	sessions, err := memory.New(100)
	if err != nil {
		t.Fatal(err)
	}

	return &accountMemory{
		SessionStore: sessions, accounts: make(map[string]Account),
		challenges: make(map[auth.Digest]memoryChallenge),
	}
}

func (m *accountMemory) Enroll(
	ctx context.Context,
	a Account,
	c Challenge,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.fail != nil {
		return m.fail
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if _, ok := m.accounts[a.Email]; ok {
		return ErrConflict
	}

	m.accounts[a.Email] = a
	m.challenges[c.Digest] = memoryChallenge{c, a.Email, a.Version}

	return nil
}

func (m *accountMemory) LookupAccount(
	ctx context.Context,
	email string,
) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.fail != nil {
		return Account{}, m.fail
	}

	if err := ctx.Err(); err != nil {
		return Account{}, err
	}

	a, ok := m.accounts[email]
	if !ok {
		return Account{}, auth.ErrNotFound
	}

	return a, nil
}

func (m *accountMemory) ReplaceChallenge(ctx context.Context, email string,
	c Challenge,
) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.fail != nil {
		return Account{}, m.fail
	}

	if err := ctx.Err(); err != nil {
		return Account{}, err
	}

	a, ok := m.accounts[email]
	if !ok || a.Disabled || a.Verified == (c.Purpose == VerifyEmail) {
		return Account{}, auth.ErrNotFound
	}

	for digest, old := range m.challenges {
		if old.account == email && old.Purpose == c.Purpose {
			delete(m.challenges, digest)
		}
	}

	m.challenges[c.Digest] = memoryChallenge{c, email, a.Version}

	return a, nil
}

func (m *accountMemory) challenge(
	p Purpose,
	d auth.Digest,
	now time.Time,
) (Account, error) {
	c, ok := m.challenges[d]

	a := m.accounts[c.account]
	if !ok || c.Purpose != p || c.version != a.Version || a.Disabled ||
		now.Before(c.CreatedAt) || !now.Before(c.ExpiresAt) ||
		a.Verified == (p == VerifyEmail) {
		return Account{}, auth.ErrNotFound
	}

	return a, nil
}

func (m *accountMemory) ChallengeAccount(ctx context.Context, p Purpose,
	d auth.Digest, now time.Time,
) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.fail != nil {
		return Account{}, m.fail
	}

	if err := ctx.Err(); err != nil {
		return Account{}, err
	}

	return m.challenge(p, d, now)
}

func (m *accountMemory) Verify(
	ctx context.Context,
	d auth.Digest,
	now time.Time,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.fail != nil {
		return m.fail
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	a, err := m.challenge(VerifyEmail, d, now)
	if err != nil {
		return err
	}

	a.Verified = true
	m.accounts[a.Email] = a
	delete(m.challenges, d)

	return nil
}

func (m *accountMemory) Reset(ctx context.Context, d auth.Digest, version int64,
	hash string, now time.Time,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	a, err := m.challenge(RecoverPassword, d, now)
	if err != nil {
		return err
	}

	if a.Version != version {
		return auth.ErrNotFound
	}

	a.Version++
	a.Hash = hash
	m.accounts[a.Email] = a
	m.invalidate(a)

	return m.DeleteSubject(ctx, a.ID)
}

func (m *accountMemory) Disable(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for email, a := range m.accounts {
		if a.ID != id {
			continue
		}

		a.Version++
		a.Disabled = true
		m.accounts[email] = a
		m.invalidate(a)

		return m.DeleteSubject(ctx, id)
	}

	return auth.ErrNotFound
}

func (m *accountMemory) invalidate(a Account) {
	for d, c := range m.challenges {
		if c.account == a.Email {
			delete(m.challenges, d)
		}
	}
}

func (m *accountMemory) Create(
	ctx context.Context,
	d auth.Digest,
	s auth.Session,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.creates++

	for _, a := range m.accounts {
		if a.ID == s.SubjectID && a.Verified && !a.Disabled &&
			s.CredentialVersion > 0 && a.Version == s.CredentialVersion {
			state := auth.AccountState{
				SubjectID:            a.ID,
				Version:              a.Version,
				Disabled:             a.Disabled,
				SecondFactorRequired: a.SecondFactorRequired,
			}
			if err := state.Accepts(s); err != nil {
				return err
			}

			return m.SessionStore.Create(ctx, d, s)
		}
	}

	return auth.ErrUnauthenticated
}

type recordingSender struct {
	mu       sync.Mutex
	messages []Notification
	fail     bool
}

func (r *recordingSender) Send(_ context.Context, n Notification) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.messages = append(r.messages, n)
	if r.fail {
		return errors.New("sensitive delivery provider error: " + n.Token)
	}

	return nil
}

func (r *recordingSender) last() Notification {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.messages[len(r.messages)-1]
}

type testLimiter struct {
	fail error
	keys []string
}

func (l *testLimiter) Allow(ctx context.Context, key string) error {
	l.keys = append(l.keys, key)
	if l.fail != nil {
		return l.fail
	}

	return ctx.Err()
}

func testService(t *testing.T) (*Service, *accountMemory, *recordingSender) {
	t.Helper()

	store := newAccountMemory(t)
	sender := &recordingSender{}

	hasher, err := NewHasher(
		Config{
			MemoryKiB:     19 * 1024,
			Iterations:    2,
			Parallelism:   1,
			MaxConcurrent: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	service, err := NewService(
		context.Background(),
		store,
		hasher,
		&testLimiter{},
		sender,
		auth.DefaultConfig(),
		DefaultLifecycleConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}

	return service, store, sender
}

const (
	oldPassword = "a long Unicode 密碼 passphrase"
	newPassword = "a different 密碼 passphrase"
)

func TestServiceLifecycle(t *testing.T) {
	s, store, sender := testService(t)

	ctx := context.Background()
	if err := s.Enroll(
		ctx,
		"Alice@Example.COM",
		[]byte(oldPassword),
	); err != nil {
		t.Fatal(err)
	}

	verification := sender.last()
	if verification.Email != "alice@example.com" {
		t.Fatal("canonical delivery identifier")
	}

	if err := s.Enroll(
		ctx,
		"alice@example.com",
		[]byte(newPassword),
	); err != nil {
		t.Fatal(err)
	}

	if len(sender.messages) != 1 {
		t.Fatal("duplicate enrollment changed challenge")
	}

	for _, email := range []string{"alice@example.com", "unknown@example.com"} {
		if _, err := s.SignIn(
			ctx,
			email,
			[]byte(oldPassword),
		); !errors.Is(
			err,
			ErrInvalidCredentials,
		) {
			t.Fatalf("public denial for %s: %v", email, err)
		}
	}

	if store.creates != 0 {
		t.Fatal("unverified sign-in attempted session issuance")
	}

	if err := s.ResetPassword(
		ctx,
		verification.Token,
		[]byte(newPassword),
	); !errors.Is(
		err,
		ErrInvalidChallenge,
	) {
		t.Fatal("verification token used for recovery")
	}

	if err := s.VerifyEmail(ctx, verification.Token); err != nil {
		t.Fatal(err)
	}

	if err := s.VerifyEmail(
		ctx,
		verification.Token,
	); !errors.Is(
		err,
		ErrInvalidChallenge,
	) {
		t.Fatal("replayed verification")
	}

	if _, err := s.SignIn(
		ctx,
		"alice@example.com",
		[]byte("wrong password"),
	); !errors.Is(
		err,
		ErrInvalidCredentials,
	) {
		t.Fatal(err)
	}

	issued, err := s.SignIn(ctx, "ALICE@example.com", []byte(oldPassword))
	if err != nil {
		t.Fatal(err)
	}

	rotated, err := s.Sessions().Rotate(ctx, issued.Token)
	if err != nil || rotated.Session.CredentialVersion != 1 {
		t.Fatal("lost rotation fence", err)
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
		ErrInvalidChallenge,
	) {
		t.Fatal("wrong purpose")
	}

	if err := s.ResetPassword(
		ctx,
		recovery.Token,
		[]byte(newPassword),
	); err != nil {
		t.Fatal(err)
	}

	if err := s.ResetPassword(
		ctx,
		recovery.Token,
		[]byte(newPassword),
	); !errors.Is(
		err,
		ErrInvalidChallenge,
	) {
		t.Fatal("replayed recovery")
	}

	if _, err := s.Sessions().
		Authenticate(ctx, rotated.Token); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatal("reset left session")
	}

	if _, err := s.SignIn(
		ctx,
		"alice@example.com",
		[]byte(oldPassword),
	); !errors.Is(
		err,
		ErrInvalidCredentials,
	) {
		t.Fatal("old password")
	}

	fresh, err := s.SignIn(ctx, "alice@example.com", []byte(newPassword))
	if err != nil {
		t.Fatal(err)
	}

	a, _ := store.LookupAccount(ctx, "alice@example.com")
	if err := s.Disable(ctx, a.ID); err != nil {
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
		[]byte(newPassword),
	); !errors.Is(
		err,
		ErrInvalidCredentials,
	) {
		t.Fatal("disabled signin")
	}
}

func (m *accountMemory) CreateAuthenticated(
	ctx context.Context,
	digest auth.Digest,
	session auth.Session,
) error {
	if session.Authentication.IsZero() {
		return auth.ErrUnauthenticated
	}

	return m.Create(ctx, digest, session)
}
