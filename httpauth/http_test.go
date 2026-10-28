package httpauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/httpauth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

func setup(t *testing.T) (*httpauth.Transport, auth.IssuedSession) {
	t.Helper()

	store, _ := memory.New(10)

	manager, err := auth.New(store, auth.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	origins := []string{"https://app.example.com"}

	transport, err := httpauth.New(manager, httpauth.Config{
		TrustedOrigins: origins,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Mutating caller-owned configuration must not change trusted origins.
	origins[0] = "https://evil.example.com"

	issued, err := manager.Start(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}

	return transport, issued
}

func TestCookieAttributes(t *testing.T) {
	transport, issued := setup(t)

	w := httptest.NewRecorder()
	if err := transport.WriteCookie(w, issued); err != nil {
		t.Fatal(err)
	}

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("expected one session cookie")
	}

	cookie := cookies[0]
	if cookie.Name != httpauth.CookieName || cookie.Value != issued.Token ||
		!cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" ||
		cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("session cookie attributes changed")
	}

	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cookie response may be cached")
	}

	cleared := httptest.NewRecorder()
	transport.ClearCookie(cleared)

	cookies = cleared.Result().Cookies()
	if cookies[len(cookies)-1].MaxAge != -1 {
		t.Fatal("clear cookie did not expire browser state")
	}
}

func TestRequireAndOrigin(t *testing.T) {
	transport, issued := setup(t)
	called := false
	handler := transport.Require(http.HandlerFunc(func(
		w http.ResponseWriter, r *http.Request,
	) {
		session, ok := httpauth.FromContext(r.Context())
		if !ok || session.SubjectID != "alice" {
			t.Error("verified identity missing")
		}

		called = true

		w.WriteHeader(http.StatusNoContent)
	}))

	for _, test := range []struct {
		name    string
		method  string
		origins []string
		tokens  []string
		want    int
	}{
		{"read", "GET", nil, []string{issued.Token}, 204},
		{
			"write", "POST",
			[]string{"https://app.example.com"},
			[]string{issued.Token},
			204,
		},
		{"missing origin", "POST", nil, []string{issued.Token}, 403},
		{
			"evil origin", "POST",
			[]string{"https://evil.example.com"},
			[]string{issued.Token},
			403,
		},
		{"null origin", "POST", []string{"null"}, []string{issued.Token}, 403},
		{"multiple origins", "POST", []string{
			"https://app.example.com", "https://evil.example.com",
		}, []string{issued.Token}, 403},
		{"missing cookie", "GET", nil, nil, 401},
		{"bad cookie", "GET", nil, []string{"bad"}, 401},
		{
			"ambiguous cookie", "GET", nil,
			[]string{issued.Token, issued.Token},
			401,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			called = false

			r := httptest.NewRequest(
				test.method,
				"https://api.example.com",
				nil,
			)
			for _, origin := range test.origins {
				r.Header.Add("Origin", origin)
			}

			for _, token := range test.tokens {
				r.AddCookie(
					&http.Cookie{Name: httpauth.CookieName, Value: token},
				)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			if w.Code != test.want || called != (test.want == 204) {
				t.Fatalf(
					"status=%d, called=%v, want=%d",
					w.Code,
					called,
					test.want,
				)
			}
		})
	}
}

func TestRejectInvalidOrigins(t *testing.T) {
	store, _ := memory.New(10)

	manager, _ := auth.New(store, auth.DefaultConfig())
	for _, origin := range []string{
		"*", "https://*.example.com", "http://example.com",
		"https://app.example.com/path", "https://user@app.example.com",
		"https://app.example.com?x=y", "null", "",
	} {
		if _, err := httpauth.New(manager, httpauth.Config{
			TrustedOrigins: []string{origin},
		}); err == nil {
			t.Fatalf("unsafe origin accepted: %q", origin)
		}
	}
}

func TestLoginGuard(t *testing.T) {
	transport, _ := setup(t)
	called := false
	handler := transport.Guard(http.HandlerFunc(func(
		w http.ResponseWriter, _ *http.Request,
	) {
		called = true

		w.WriteHeader(204)
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "https://api.example.com/auth/login", nil)
	handler.ServeHTTP(w, r)

	if called || w.Code != 403 {
		t.Fatal("unauthenticated login accepted without Origin")
	}
}
