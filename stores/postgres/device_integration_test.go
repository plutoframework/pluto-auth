package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/device"
	"github.com/plutoframework/pluto-auth/stores/postgres"
)

type allowAll struct{}

func (allowAll) AuthorizeDelegation(
	context.Context, string, string, []string,
) error {
	return nil
}

func (allowAll) Allow(context.Context, string) error { return nil }

func newDeviceService(t *testing.T) (
	*device.Service, *auth.Manager, func(time.Duration),
) {
	t.Helper()

	pool := testPool(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, postgres.DeviceSchema); err != nil {
		t.Fatal(err)
	}

	sessions, err := postgres.New(pool)
	if err != nil {
		t.Fatal(err)
	}

	store, err := postgres.NewDevice(pool)
	if err != nil {
		t.Fatal(err)
	}

	var mutex sync.Mutex

	now := time.Now().UTC().Truncate(time.Microsecond)
	clock := func() time.Time {
		mutex.Lock()
		defer mutex.Unlock()

		return now
	}
	advance := func(d time.Duration) {
		mutex.Lock()
		defer mutex.Unlock()

		now = now.Add(d)
	}

	config := auth.DefaultConfig()
	config.Clock = clock

	manager, err := auth.New(sessions, config)
	if err != nil {
		t.Fatal(err)
	}

	service, err := device.New(store, device.Config{
		Clients: []device.Client{{
			ID: "cli", Name: "CLI", ActorType: "agent",
			Scopes: []string{"requests.read", "requests.write"},
		}},
		Sessions:        manager,
		Authorizer:      allowAll{},
		Limiter:         allowAll{},
		VerificationURI: "https://app.example.test/device",
		Clock:           clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	return service, manager, advance
}

func TestPostgresDeviceFlow(t *testing.T) {
	service, manager, advance := newDeviceService(t)
	ctx := context.Background()

	code, err := service.Authorize(ctx, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}

	request := device.TokenRequest{
		GrantType: device.GrantDeviceCode, ClientID: "cli",
		DeviceCode: code.DeviceCode,
	}

	advance(6 * time.Second)

	if _, err := service.Token(ctx, request); !errors.Is(
		err, device.ErrAuthorizationPending) {
		t.Fatalf("expected pending, got %v", err)
	}

	// Polling faster than the interval.
	if _, err := service.Token(ctx, request); !errors.Is(
		err, device.ErrSlowDown) {
		t.Fatalf("expected slow_down, got %v", err)
	}

	issued, err := manager.Start(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}

	err = manager.WithIdentity(ctx, issued.Token,
		func(ctx context.Context, identity *auth.Identity) error {
			return service.Approve(ctx, identity, code.UserCode, "acme",
				[]string{"requests.write"})
		})
	if err != nil {
		t.Fatal(err)
	}

	advance(16 * time.Second)

	tokens, err := service.Token(ctx, request)
	if err != nil || tokens.Scope != "requests.write" ||
		tokens.Tenant != "acme" {
		t.Fatalf("token: %+v %v", tokens, err)
	}

	// Single use.
	advance(16 * time.Second)

	if _, err := service.Token(ctx, request); !errors.Is(
		err, device.ErrInvalidGrant) {
		t.Fatalf("code reuse: %v", err)
	}

	digest, _ := auth.TokenDigest(tokens.AccessToken)

	session, err := service.Session(ctx, digest, time.Now().UTC())
	if err != nil || session.SubjectID != "alice" ||
		session.Delegation == nil || session.Delegation.ClientID != "cli" {
		t.Fatalf("session: %+v %v", session, err)
	}

	// Rotation, narrowing, no widening, reuse revokes the family.
	refresh := device.TokenRequest{
		GrantType: device.GrantRefreshToken, ClientID: "cli",
		RefreshToken: tokens.RefreshToken,
		Scopes:       []string{"requests.read"},
	}

	if _, err := service.Token(ctx, refresh); !errors.Is(
		err, device.ErrInvalidScope) {
		t.Fatalf("widening must fail: %v", err)
	}

	refresh.Scopes = []string{"requests.write"}

	second, err := service.Token(ctx, refresh)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.Session(ctx, digest, time.Now().UTC()); err == nil {
		t.Fatal("rotated access token must be revoked")
	}

	refresh.Scopes = nil

	if _, err := service.Token(ctx, refresh); !errors.Is(
		err, device.ErrInvalidGrant) {
		t.Fatalf("reuse: %v", err)
	}

	secondDigest, _ := auth.TokenDigest(second.AccessToken)
	if _, err := service.Session(
		ctx,
		secondDigest,
		time.Now().UTC(),
	); err == nil {
		t.Fatal("reuse must revoke the whole family, including live tokens")
	}

	refresh.RefreshToken = second.RefreshToken

	if _, err := service.Token(ctx, refresh); !errors.Is(
		err, device.ErrInvalidGrant) {
		t.Fatalf("newest refresh token survived reuse: %v", err)
	}
}

func TestPostgresDeviceRevocation(t *testing.T) {
	service, manager, advance := newDeviceService(t)
	ctx := context.Background()

	issue := func() device.TokenResponse {
		code, err := service.Authorize(ctx, "cli", []string{"requests.read"})
		if err != nil {
			t.Fatal(err)
		}

		owner, err := manager.Start(ctx, "alice")
		if err != nil {
			t.Fatal(err)
		}

		err = manager.WithIdentity(ctx, owner.Token,
			func(ctx context.Context, identity *auth.Identity) error {
				return service.Approve(ctx, identity, code.UserCode, "acme",
					[]string{"requests.read"})
			})
		if err != nil {
			t.Fatal(err)
		}

		advance(6 * time.Second)

		tokens, err := service.Token(ctx, device.TokenRequest{
			GrantType: device.GrantDeviceCode, ClientID: "cli",
			DeviceCode: code.DeviceCode,
		})
		if err != nil {
			t.Fatal(err)
		}

		return tokens
	}

	live := func(tokens device.TokenResponse) bool {
		digest, _ := auth.TokenDigest(tokens.AccessToken)
		_, err := service.Session(ctx, digest, time.Now().UTC())

		return err == nil
	}

	first := issue()
	if !live(first) {
		t.Fatal("fresh token rejected")
	}

	if err := service.Revoke(ctx, first.RefreshToken); err != nil {
		t.Fatal(err)
	}

	if live(first) {
		t.Fatal("revoked token accepted")
	}

	second := issue()

	if err := service.RevokeSubject(ctx, "alice"); err != nil {
		t.Fatal(err)
	}

	if live(second) {
		t.Fatal("subject revocation missed a family")
	}

	if _, err := service.Authorize(ctx, "cli", nil); err != nil {
		t.Fatal(err)
	}
}
