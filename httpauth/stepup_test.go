package httpauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/httpauth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

// This controlled store tests HTTP behavior; production needs an atomic account fence.
type evidenceStore struct{ auth.SessionStore }

func (store evidenceStore) CreateAuthenticated(
	ctx context.Context,
	digest auth.Digest,
	session auth.Session,
) error {
	return store.Create(ctx, digest, session)
}

func TestRequireAuthenticationChecksFreshnessAndOrigin(t *testing.T) {
	now := time.Now().UTC()

	store, err := memory.New(8)
	if err != nil {
		t.Fatal(err)
	}

	config := auth.DefaultConfig()
	config.Clock = func() time.Time { return now }

	manager, err := auth.New(evidenceStore{store}, config)
	if err != nil {
		t.Fatal(err)
	}

	ceremony, err := auth.NewCeremony(
		auth.AccountState{SubjectID: "reader", Version: 1},
		false,
		now,
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}

	ceremony, err = ceremony.PrimaryVerified(auth.MethodPassword, now)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := ceremony.Complete(now)
	if err != nil {
		t.Fatal(err)
	}

	issued, err := manager.StartAuthenticated(context.Background(), proof)
	if err != nil {
		t.Fatal(err)
	}

	transport, err := httpauth.New(
		manager,
		httpauth.Config{TrustedOrigins: []string{"https://app.example.test"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	calls := 0

	handler, err := transport.RequireAuthentication(
		auth.Requirement{MaxAge: 5 * time.Minute},
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++

			w.WriteHeader(http.StatusNoContent)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	request := func(token, origin string) int {
		r := httptest.NewRequest(
			http.MethodPost,
			"https://app.example.test/sensitive",
			nil,
		)
		if token != "" {
			r.AddCookie(&http.Cookie{Name: httpauth.CookieName, Value: token})
		}

		if origin != "" {
			r.Header.Set("Origin", origin)
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		return w.Code
	}

	if request("", "https://app.example.test") != 401 ||
		request(issued.Token, "https://wrong.example.test") != 403 ||
		request(issued.Token, "https://app.example.test") != 204 {
		t.Fatal("authentication or Origin guard changed")
	}

	now = now.Add(5 * time.Minute)

	if request(issued.Token, "https://app.example.test") != 403 || calls != 1 {
		t.Fatal("stale authentication reached the sensitive operation")
	}
}
