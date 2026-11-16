package httpauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/httpauth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

func serviceFixture(t *testing.T) (
	*httpauth.Transport,
	*auth.Integrations,
	*auth.Manager,
) {
	t.Helper()

	sessions, _ := memory.New(10)
	manager, _ := auth.New(sessions, auth.DefaultConfig())

	tokens, err := memory.NewIntegrationStore(10)
	if err != nil {
		t.Fatal(err)
	}

	integrations, err := auth.NewIntegrations(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	transport, err := httpauth.New(manager, httpauth.Config{
		TrustedOrigins: []string{"https://app.example.com"},
		AllowBearer:    true,
		Integrations:   integrations,
	})
	if err != nil {
		t.Fatal(err)
	}

	return transport, integrations, manager
}

func serve(
	handler http.Handler,
	headers []string,
	cookie string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest("POST", "https://api.example.com", nil)
	for _, header := range headers {
		request.Header.Add("Authorization", header)
	}

	if cookie != "" {
		request.AddCookie(
			&http.Cookie{Name: httpauth.CookieName, Value: cookie},
		)
	}

	writer := httptest.NewRecorder()
	handler.ServeHTTP(writer, request)

	return writer
}

func TestRequireServiceResolvesServiceIdentity(t *testing.T) {
	transport, integrations, manager := serviceFixture(t)
	ctx := context.Background()

	issued, err := integrations.Issue(ctx, "tenant-9", "ci-runner")
	if err != nil {
		t.Fatal(err)
	}

	handler := transport.RequireService(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			identity, ok := httpauth.ServiceFromContext(r.Context())
			if !ok || identity.TenantID != "tenant-9" ||
				identity.Principal != "ci-runner" || !identity.IsService() {
				t.Fatalf("wrong service identity: %+v", identity)
			}

			if _, ok := httpauth.FromContext(r.Context()); ok {
				t.Fatal("service caller visible as a user session")
			}

			if _, ok := httpauth.IdentityFromContext(r.Context()); ok {
				t.Fatal("service caller visible as a session identity")
			}

			w.WriteHeader(204)
		},
	))

	if got := serve(
		handler,
		[]string{"Bearer " + issued.Secret},
		"",
	).Code; got != 204 {
		t.Fatalf("valid token status=%d", got)
	}

	if got := serve(
		handler,
		[]string{"bearer " + issued.Secret},
		"",
	).Code; got != 204 {
		t.Fatalf("lowercase scheme status=%d", got)
	}

	session, err := manager.Start(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}

	for name, test := range map[string]struct {
		headers []string
		cookie  string
	}{
		"none":            {},
		"session bearer":  {[]string{"Bearer " + session.Token}, ""},
		"session cookie":  {nil, session.Token},
		"mixed":           {[]string{"Bearer " + issued.Secret}, session.Token},
		"duplicate":       {[]string{"Bearer " + issued.Secret, "Bearer " + issued.Secret}, ""},
		"empty":           {[]string{"Bearer "}, ""},
		"wrong scheme":    {[]string{"Basic " + issued.Secret}, ""},
		"malformed":       {[]string{"Bearer not-a-token"}, ""},
		"padded":          {[]string{"Bearer  " + issued.Secret}, ""},
		"unknown but fit": {[]string{"Bearer " + strings.Repeat("A", 43)}, ""},
	} {
		got := serve(handler, test.headers, test.cookie)
		if got.Code != 401 || got.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: status=%d", name, got.Code)
		}

		if strings.Contains(got.Body.String(), issued.Secret) {
			t.Fatalf("%s: secret echoed", name)
		}
	}
}

func TestRequireServiceRevocationAndRotationApplyNextRequest(t *testing.T) {
	transport, integrations, _ := serviceFixture(t)
	ctx := context.Background()

	issued, err := integrations.Issue(ctx, "tenant", "worker")
	if err != nil {
		t.Fatal(err)
	}

	handler := transport.RequireService(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) },
	))
	bearer := func(secret string) int {
		return serve(handler, []string{"Bearer " + secret}, "").Code
	}

	rotated, err := integrations.Rotate(ctx, issued.Token.ID)
	if err != nil {
		t.Fatal(err)
	}

	if bearer(issued.Secret) != 401 || bearer(rotated.Secret) != 204 {
		t.Fatal("rotation did not switch secrets at once")
	}

	if err := integrations.Revoke(ctx, issued.Token.ID); err != nil {
		t.Fatal(err)
	}

	if bearer(rotated.Secret) != 401 {
		t.Fatal("revoked token still authenticates")
	}
}

func TestIntegrationTokenIsNotASessionAndFailsClosed(t *testing.T) {
	transport, integrations, _ := serviceFixture(t)

	issued, err := integrations.Issue(context.Background(), "t", "p")
	if err != nil {
		t.Fatal(err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	})

	if got := serve(
		transport.Require(next),
		[]string{"Bearer " + issued.Secret},
		"",
	).Code; got != 401 {
		t.Fatalf("integration token accepted as session: %d", got)
	}

	if got := serve(
		transport.RequireIdentity(next),
		[]string{"Bearer " + issued.Secret},
		"",
	).Code; got != 401 {
		t.Fatalf("integration token accepted as identity: %d", got)
	}

	sessions, _ := memory.New(10)
	manager, _ := auth.New(sessions, auth.DefaultConfig())

	plain, err := httpauth.New(manager, httpauth.Config{
		TrustedOrigins: []string{"https://app.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := serve(
		plain.RequireService(next),
		[]string{"Bearer " + issued.Secret},
		"",
	).Code; got != 401 {
		t.Fatalf("unconfigured transport accepted token: %d", got)
	}
}
