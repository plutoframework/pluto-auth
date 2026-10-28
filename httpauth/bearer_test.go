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

func TestBearerOptInAndAmbiguousCredentials(t *testing.T) {
	store, _ := memory.New(10)
	manager, _ := auth.New(store, auth.DefaultConfig())

	issued, err := manager.Start(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}

	for _, enabled := range []bool{false, true} {
		transport, err := httpauth.New(manager, httpauth.Config{
			TrustedOrigins: []string{"https://app.example.com"},
			AllowBearer:    enabled,
		})
		if err != nil {
			t.Fatal(err)
		}

		for _, test := range []struct {
			name    string
			headers []string
			cookie  bool
			want    int
		}{
			{"bearer", []string{"Bearer " + issued.Token}, false, 204},
			{"lowercase", []string{"bearer " + issued.Token}, false, 204},
			{"mixed", []string{"Bearer " + issued.Token}, true, 401},
			{"duplicate", []string{"Bearer " + issued.Token, "Bearer " + issued.Token}, false, 401},
			{"empty", []string{"Bearer "}, false, 401},
			{"wrong scheme", []string{"Basic abc"}, false, 401},
		} {
			t.Run(test.name, func(t *testing.T) {
				request := httptest.NewRequest(
					"POST",
					"https://api.example.com",
					nil,
				)
				for _, header := range test.headers {
					request.Header.Add("Authorization", header)
				}

				if test.cookie {
					request.AddCookie(
						&http.Cookie{
							Name:  httpauth.CookieName,
							Value: issued.Token,
						},
					)
				}

				writer := httptest.NewRecorder()
				transport.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					session, ok := httpauth.FromContext(r.Context())

					token, err := transport.Token(r)
					if !ok || session.SubjectID != "alice" || err != nil ||
						token != issued.Token {
						t.Fatal(
							"verified bearer identity or revocation credential lost",
						)
					}

					w.WriteHeader(204)
				})).
					ServeHTTP(writer, request)

				want := test.want
				if !enabled {
					want = 401
				}

				if writer.Code != want {
					t.Fatalf("status=%d, want=%d", writer.Code, want)
				}
			})
		}
	}
}
