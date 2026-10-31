package totphttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/httpauth"
	"github.com/plutoframework/pluto-auth/methods/totp"
)

type (
	unusedStore     struct{ totp.Store }
	unusedProtector struct{ totp.Protector }
	limiter         struct{}
)

func (limiter) Allow(context.Context, string) error { return nil }
func TestDeniedRequests(t *testing.T) {
	service, err := totp.New(
		&unusedStore{},
		&unusedProtector{},
		limiter{},
		totp.Config{Issuer: "Test", Sessions: auth.DefaultConfig()},
	)
	if err != nil {
		t.Fatal(err)
	}

	called := 0

	handler, err := New(service, Config{
		Transport: httpauth.Config{
			TrustedOrigins: []string{"https://app.example"},
		},
		Ingress: func(next http.Handler) http.Handler { return next },
		Primary: func(context.Context, string, []byte) (auth.Ceremony, error) {
			called++
			return auth.Ceremony{}, totp.ErrDenied
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, body := range []string{
		`{"email":"a","Email":"b"}`, `{"password":"one","password":"two"}`,
		`{"unknown":"field"}`, `[]`, `null`, `{} {}`, "{\"email\":\"\xff\"}", strings.Repeat("x", 8193),
	} {
		req := httptest.NewRequest(
			http.MethodPost,
			"https://app.example/begin",
			strings.NewReader(body),
		)
		req.Header.Set("Origin", "https://app.example")
		req.Header.Set("Content-Type", "application/json")

		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)

		if response.Code != 401 ||
			response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("malformed request accepted")
		}
	}

	if called != 0 {
		t.Fatal("primary ran for malformed request")
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"https://app.example/begin",
		strings.NewReader(`{}`),
	)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)

	if response.Code != 403 || called != 0 {
		t.Fatal("Origin bypass")
	}
}

func TestDuplicateBrowserCookies(t *testing.T) {
	service, err := totp.New(
		&unusedStore{},
		&unusedProtector{},
		limiter{},
		totp.Config{Issuer: "Test", Sessions: auth.DefaultConfig()},
	)
	if err != nil {
		t.Fatal(err)
	}

	handler, err := New(service, Config{
		Transport: httpauth.Config{
			TrustedOrigins: []string{"https://app.example"},
		},
		Ingress: func(next http.Handler) http.Handler { return next },
		Primary: func(context.Context, string, []byte) (auth.Ceremony, error) { return auth.Ceremony{}, totp.ErrDenied },
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, first := range []string{"", totp.Browser()} {
		body := `{"challenge":"` + totp.Browser() + `","code":"123456"}`
		req := httptest.NewRequest(
			http.MethodPost,
			"https://app.example/finish",
			strings.NewReader(body),
		)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://app.example")
		req.AddCookie(&http.Cookie{Name: BrowserCookie, Value: first})
		req.AddCookie(&http.Cookie{Name: BrowserCookie, Value: totp.Browser()})

		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)

		if response.Code != 401 {
			t.Fatal("duplicate browser cookies accepted")
		}
	}
}

func FuzzBoundedJSON(f *testing.F) {
	f.Add(`{"challenge":"hello","recovery":true}`)
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 9000 {
			return
		}

		req := httptest.NewRequest(
			http.MethodPost,
			"https://app.example/finish",
			strings.NewReader(body),
		)
		req.Header.Set("Content-Type", "application/json")

		response := httptest.NewRecorder()

		var input finishInput

		_ = decode(response, req, &input)
	})
}
