package httpauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/httpauth"
)

func TestHTTPIdentityPreservesCredentialAndOriginBoundary(t *testing.T) {
	transport, issued := setup(t)

	var retained *auth.Identity

	calls := 0
	handler := transport.RequireIdentity(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := httpauth.IdentityFromContext(r.Context())
			if !ok {
				t.Fatal("opaque identity missing")
			}

			retained = identity

			err := identity.Use(
				r.Context(),
				func(_ context.Context, subject string) error {
					if subject != "alice" {
						t.Fatal("wrong verified subject")
					}

					calls++

					return nil
				},
			)
			if err != nil {
				t.Fatal(err)
			}

			w.WriteHeader(http.StatusNoContent)
		}),
	)

	for _, test := range []struct {
		origin, bearer string
		want           int
	}{
		{"", "", http.StatusForbidden},
		{"https://evil.example.com", "", http.StatusForbidden},
		{"https://app.example.com", "Bearer " + issued.Token, http.StatusUnauthorized},
		{"https://app.example.com", "", http.StatusNoContent},
	} {
		request := httptest.NewRequest(
			http.MethodPost,
			"https://app.example.com/write",
			nil,
		)
		request.AddCookie(
			&http.Cookie{Name: httpauth.CookieName, Value: issued.Token},
		)

		if test.origin != "" {
			request.Header.Set("Origin", test.origin)
		}

		if test.bearer != "" {
			request.Header.Set("Authorization", test.bearer)
		}

		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)

		if response.Code != test.want {
			t.Fatalf("status=%d want=%d", response.Code, test.want)
		}
	}

	if calls != 1 {
		t.Fatalf("handler effects=%d", calls)
	}

	if err := retained.Use(
		context.Background(),
		func(context.Context, string) error {
			t.Fatal("HTTP identity escaped")

			return nil
		},
	); !errors.Is(
		err,
		auth.ErrUnauthenticated,
	) {
		t.Fatal(err)
	}
}
