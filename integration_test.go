package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

// recordingIntegrationStore captures everything handed to persistence.
type recordingIntegrationStore struct {
	auth.IntegrationStore
	seen []string
	fail error
}

func (s *recordingIntegrationStore) Issue(
	ctx context.Context,
	digest auth.Digest,
	token auth.IntegrationToken,
) error {
	s.seen = append(s.seen, fmt.Sprintf("%x %+v", digest, token))

	if s.fail != nil {
		return s.fail
	}

	return s.IntegrationStore.Issue(ctx, digest, token)
}

func (s *recordingIntegrationStore) Rotate(
	ctx context.Context,
	id string,
	digest auth.Digest,
) (auth.IntegrationToken, error) {
	s.seen = append(s.seen, fmt.Sprintf("%s %x", id, digest))

	return s.IntegrationStore.Rotate(ctx, id, digest)
}

func (s *recordingIntegrationStore) Lookup(
	ctx context.Context,
	digest auth.Digest,
) (auth.IntegrationToken, error) {
	if s.fail != nil {
		return auth.IntegrationToken{}, s.fail
	}

	return s.IntegrationStore.Lookup(ctx, digest)
}

func testIntegrations(
	t *testing.T,
) (*auth.Integrations, *recordingIntegrationStore) {
	t.Helper()

	inner, err := memory.NewIntegrationStore(100)
	if err != nil {
		t.Fatal(err)
	}

	store := &recordingIntegrationStore{IntegrationStore: inner}

	integrations, err := auth.NewIntegrations(store, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	return integrations, store
}

func TestIntegrationIssuePersistsOnlyDigest(t *testing.T) {
	integrations, store := testIntegrations(t)
	ctx := context.Background()

	issued, err := integrations.Issue(ctx, "tenant-1", "billing-worker")
	if err != nil {
		t.Fatal(err)
	}

	digest, err := auth.TokenDigest(issued.Secret)
	if err != nil {
		t.Fatalf("secret is not a canonical token: %v", err)
	}

	if len(store.seen) != 1 ||
		!strings.Contains(store.seen[0], fmt.Sprintf("%x", digest)) {
		t.Fatalf("store did not receive the digest: %v", store.seen)
	}

	for _, seen := range store.seen {
		if strings.Contains(seen, issued.Secret) {
			t.Fatal("plaintext secret reached the store")
		}
	}

	identity, err := integrations.Authenticate(ctx, issued.Secret)
	if err != nil {
		t.Fatal(err)
	}

	if identity.TenantID != "tenant-1" ||
		identity.Principal != "billing-worker" ||
		identity.TokenID != issued.Token.ID || !identity.IsService() {
		t.Fatalf("unexpected identity: %+v", identity)
	}

	other, err := integrations.Issue(ctx, "tenant-1", "billing-worker")
	if err != nil || other.Secret == issued.Secret {
		t.Fatal("tokens must be independent random secrets", err)
	}
}

func TestIntegrationSecretNeverLeaks(t *testing.T) {
	integrations, store := testIntegrations(t)
	ctx := context.Background()

	issued, err := integrations.Issue(ctx, "tenant-1", "worker")
	if err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	logger.Info("issued", "token", issued, "group", issued.LogValue())
	logger.Info("token", "id", issued.Token)

	encoded, err := json.Marshal(issued)
	if err != nil {
		t.Fatal(err)
	}

	outputs := []string{
		logs.String(),
		string(encoded),
		fmt.Sprintf(
			"%v|%+v|%#v|%s|%d|%x",
			issued, issued, issued, issued, issued, issued,
		),
	}

	// Errors from every failing path must not echo the presented secret.
	store.fail = errors.New("database unavailable")

	_, err = integrations.Authenticate(ctx, issued.Secret)
	if err == nil {
		t.Fatal("store failure ignored")
	}

	outputs = append(outputs, err.Error())

	store.fail = nil

	for _, bad := range []string{
		issued.Secret + "x", issued.Secret[:42], "!" + issued.Secret[1:],
	} {
		_, err := integrations.Authenticate(ctx, bad)
		if !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("malformed token accepted: %v", err)
		}

		outputs = append(outputs, err.Error())
	}

	rotated, err := integrations.Rotate(ctx, issued.Token.ID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = integrations.Authenticate(ctx, issued.Secret)
	outputs = append(outputs, err.Error(), fmt.Sprintf("%v", rotated))

	store.fail = errors.New("issue failed")
	_, err = integrations.Issue(ctx, "tenant-1", "other")
	outputs = append(outputs, err.Error())

	outputs = append(outputs, store.seen...)

	for _, output := range outputs {
		if strings.Contains(output, issued.Secret) ||
			strings.Contains(output, rotated.Secret) {
			t.Fatalf("secret leaked: %s", output)
		}
	}
}

func TestIntegrationRevokeAndRotate(t *testing.T) {
	integrations, _ := testIntegrations(t)
	ctx := context.Background()

	first, err := integrations.Issue(ctx, "tenant-1", "worker")
	if err != nil {
		t.Fatal(err)
	}

	rotated, err := integrations.Rotate(ctx, first.Token.ID)
	if err != nil {
		t.Fatal(err)
	}

	if rotated.Secret == first.Secret || rotated.Token.ID != first.Token.ID ||
		rotated.Token.TenantID != "tenant-1" ||
		rotated.Token.Principal != "worker" {
		t.Fatalf("rotation changed identity or reused secret: %+v", rotated)
	}

	if _, err := integrations.Authenticate(
		ctx,
		first.Secret,
	); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatalf("old secret survived rotation: %v", err)
	}

	if _, err := integrations.Authenticate(ctx, rotated.Secret); err != nil {
		t.Fatalf("new secret rejected: %v", err)
	}

	for range 2 { // idempotent
		if err := integrations.Revoke(ctx, first.Token.ID); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := integrations.Authenticate(
		ctx,
		rotated.Secret,
	); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatalf("revoked token authenticated: %v", err)
	}

	if _, err := integrations.Rotate(
		ctx,
		first.Token.ID,
	); !errors.Is(
		err,
		auth.ErrNotFound,
	) {
		t.Fatalf("revoked token rotated: %v", err)
	}

	if _, err := integrations.Rotate(
		ctx,
		"missing",
	); !errors.Is(
		err,
		auth.ErrNotFound,
	) {
		t.Fatalf("unknown token rotated: %v", err)
	}
}

func TestIntegrationValidationAndCancellation(t *testing.T) {
	integrations, _ := testIntegrations(t)
	ctx := context.Background()

	for _, bad := range [][2]string{
		{"", "worker"},
		{"tenant", ""},
		{" tenant", "worker"},
		{"tenant", "wor\nker"},
		{strings.Repeat("a", 257), "worker"},
	} {
		if _, err := integrations.Issue(
			ctx,
			bad[0],
			bad[1],
		); !errors.Is(
			err,
			auth.ErrInvalidIntegration,
		) {
			t.Fatalf("accepted %q: %v", bad, err)
		}
	}

	if _, err := integrations.Authenticate(
		ctx,
		"",
	); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatal("empty token accepted")
	}

	// A well formed but unknown token is rejected the same way.
	issued, err := integrations.Issue(ctx, "tenant", "worker")
	if err != nil {
		t.Fatal(err)
	}

	unknown := "A" + issued.Secret[1:]
	if unknown == issued.Secret {
		unknown = "B" + issued.Secret[1:]
	}

	if _, err := integrations.Authenticate(
		ctx,
		unknown,
	); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatalf("unknown token accepted: %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	if _, err := integrations.Authenticate(
		cancelled,
		issued.Secret,
	); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatalf("cancellation ignored: %v", err)
	}

	if _, err := auth.NewIntegrations(nil, time.Now); err == nil {
		t.Fatal("nil store accepted")
	}
}
