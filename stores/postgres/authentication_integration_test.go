package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
)

func TestPostgresAuthenticationEvidenceAndRequiredFactor(t *testing.T) {
	service, store, sender, _ := localSetup(t)
	enrollVerified(t, service, sender)

	ctx := context.Background()

	issued, err := service.SignIn(
		ctx,
		"alice@example.com",
		[]byte(enrollmentPassword),
	)
	if err != nil {
		t.Fatal(err)
	}

	original, err := service.Sessions().Authenticate(ctx, issued.Token)
	if err != nil || original.Authentication.Primary != auth.MethodPassword {
		t.Fatal("password authentication evidence was not persisted", err)
	}

	if err := service.Sessions().CheckAuthentication(original,
		auth.Requirement{MaxAge: time.Minute}); err != nil {
		t.Fatal("fresh password proof rejected", err)
	}

	if err := store.SetSecondFactorRequired(
		ctx,
		issued.Session.SubjectID,
		true,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := service.Sessions().
		Authenticate(ctx, issued.Token); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatal("policy change did not revoke the old session")
	}

	if incomplete, err := service.SignIn(
		ctx,
		"alice@example.com",
		[]byte(enrollmentPassword),
	); !errors.Is(err, auth.ErrAuthenticationRequired) ||
		incomplete.Token != "" {
		t.Fatal("primary credential issued a required-factor session")
	}

	ceremony, err := service.BeginSignIn(
		ctx,
		"alice@example.com",
		[]byte(enrollmentPassword),
	)
	if err != nil || ceremony.Stage() != auth.AwaitingFactor {
		t.Fatal("expected a server-local pending-factor decision", err)
	}

	state := ceremony.Account()
	if _, err := service.Sessions().
		StartVersioned(ctx, state.SubjectID, state.Version); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatal("legacy issuance bypassed the factor policy")
	}

	// Controlled verification result; this test does not implement TOTP.
	ceremony, err = ceremony.SecondFactorVerified(auth.MethodTOTP, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	proof, err := ceremony.Complete(time.Now())
	if err != nil {
		t.Fatal(err)
	}

	complete, err := service.Sessions().StartAuthenticated(ctx, proof)
	if err != nil {
		t.Fatal(err)
	}

	rotated, err := service.Sessions().Rotate(ctx, complete.Token)
	if err != nil {
		t.Fatal(err)
	}

	persisted, err := service.Sessions().Authenticate(ctx, rotated.Token)
	if err != nil || persisted.Authentication.SecondFactor != auth.MethodTOTP ||
		!persisted.Authentication.PrimaryAt.Equal(complete.Session.Authentication.PrimaryAt.Truncate(time.Microsecond)) &&
			!persisted.Authentication.PrimaryAt.Equal(complete.Session.Authentication.PrimaryAt.Round(time.Microsecond)) {
		t.Fatal("rotation lost persisted authentication evidence", err)
	}

	if err := store.SetSecondFactorRequired(
		ctx,
		state.SubjectID,
		false,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := service.Sessions().
		Authenticate(ctx, rotated.Token); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatal("factor removal did not revoke sessions")
	}

	if _, err := service.Sessions().
		StartAuthenticated(ctx, proof); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatal("stale completed decision bypassed the shared version")
	}
}

type authenticatedBarrier struct {
	auth.AccountSessionStore
	ready   chan struct{}
	release chan struct{}
}

func (store *authenticatedBarrier) CreateAuthenticated(
	ctx context.Context, digest auth.Digest, session auth.Session,
) error {
	close(store.ready)
	<-store.release

	return store.AccountSessionStore.CreateAuthenticated(ctx, digest, session)
}

func TestPostgresPolicyChangeFencesInFlightAuthentication(t *testing.T) {
	service, store, sender, pool := localSetup(t)
	enrollVerified(t, service, sender)

	ctx := context.Background()

	ceremony, err := service.BeginSignIn(
		ctx,
		"alice@example.com",
		[]byte(enrollmentPassword),
	)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := ceremony.Complete(time.Now())
	if err != nil {
		t.Fatal(err)
	}

	barrier := &authenticatedBarrier{
		AccountSessionStore: store,
		ready:               make(chan struct{}),
		release:             make(chan struct{}),
	}

	manager, err := auth.New(barrier, auth.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)

	go func() {
		_, err := manager.StartAuthenticated(ctx, proof)
		result <- err
	}()

	<-barrier.ready

	if err := store.SetSecondFactorRequired(
		ctx,
		ceremony.Account().SubjectID,
		true,
	); err != nil {
		close(barrier.release)
		t.Fatal(err)
	}

	close(barrier.release)

	if err := <-result; !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("in-flight old policy issued a session", err)
	}

	var sessions int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM pluto_auth_sessions").
		Scan(&sessions); err != nil ||
		sessions != 0 {
		t.Fatal("rejected authentication left a usable session")
	}
}

func TestPostgresRecoveryRetainsRequiredFactor(t *testing.T) {
	service, store, sender, _ := localSetup(t)
	enrollVerified(t, service, sender)

	ctx := context.Background()

	account, err := store.LookupAccount(ctx, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}

	if err := store.SetSecondFactorRequired(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}

	if err := service.RequestRecovery(ctx, "alice@example.com"); err != nil {
		t.Fatal(err)
	}

	if err := service.ResetPassword(
		ctx,
		sender.last().Token,
		[]byte(replacementPassword),
	); err != nil {
		t.Fatal(err)
	}

	ceremony, err := service.BeginSignIn(
		ctx,
		"alice@example.com",
		[]byte(replacementPassword),
	)
	if err != nil || ceremony.Stage() != auth.AwaitingFactor {
		t.Fatal("password recovery bypassed the required factor", err)
	}
}

func TestPostgresExpiredIssuanceRollsBackSession(t *testing.T) {
	service, store, sender, pool := localSetup(t)
	enrollVerified(t, service, sender)

	ctx := context.Background()

	state, err := store.LookupAccount(ctx, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}

	// Represent a valid decision whose database lock wait outlived its deadline.
	created := time.Now().UTC().Add(-time.Hour)
	session := auth.Session{
		ID:                "expired-issuance",
		SubjectID:         state.ID,
		CredentialVersion: state.Version,
		CreatedAt:         created,
		LastSeenAt:        created,
		ExpiresAt:         created.Add(24 * time.Hour),
		Authentication: auth.Evidence{
			Primary:   auth.MethodPassword,
			PrimaryAt: created,
		},
		IssuanceDeadline: created.Add(time.Minute),
	}

	if err := store.CreateAuthenticated(
		ctx,
		auth.Digest{1},
		session,
	); !errors.Is(
		err,
		auth.ErrAuthenticationRequired,
	) {
		t.Fatal("expired in-flight authentication was accepted", err)
	}

	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM pluto_auth_sessions").
		Scan(&count); err != nil ||
		count != 0 {
		t.Fatal("failed issuance left an orphaned session")
	}
}
