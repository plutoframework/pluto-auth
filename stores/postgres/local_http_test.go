package postgres_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plutoframework/pluto-auth/httpauth"
	"github.com/plutoframework/pluto-auth/methods/password"
	"github.com/plutoframework/pluto-auth/methods/password/passwordhttp"
)

func TestLocalHTTPFlow(t *testing.T) {
	s, _, sender, _ := localSetup(t)
	ingressCalls := 0

	h, err := passwordhttp.New(s, passwordhttp.Config{
		Transport: httpauth.Config{
			TrustedOrigins: []string{"https://app.example.com"},
		},
		Ingress: func(next http.Handler) http.Handler {
			return http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					ingressCalls++

					next.ServeHTTP(w, r)
				},
			)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	request := func(method, path, body, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()

		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")

		if origin != "" {
			r.Header.Set("Origin", origin)
		}

		if cookie != nil {
			r.AddCookie(cookie)
		}

		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		return w
	}
	origin := "https://app.example.com"

	body := `{"email":"alice@example.com","password":"` + enrollmentPassword + `"}`
	if w := request("POST", "/enroll", body, "", nil); w.Code != 403 {
		t.Fatal("missing origin", w.Code)
	}

	if w := request(
		"POST",
		"/enroll",
		body,
		"https://evil.example",
		nil,
	); w.Code != 403 {
		t.Fatal("untrusted origin")
	}

	enrolled := request("POST", "/enroll", body, origin, nil)

	duplicate := request("POST", "/enroll", body, origin, nil)
	if enrolled.Code != 202 ||
		enrolled.Body.String() != duplicate.Body.String() {
		t.Fatal("duplicate outward response")
	}

	verification := sender.last().Token
	if strings.Contains(enrolled.Body.String(), verification) {
		t.Fatal("raw challenge public")
	}

	if w := request(
		"GET",
		"/verify?token="+verification,
		"",
		origin,
		nil,
	); w.Code != 405 {
		t.Fatal("GET scanner endpoint changed state")
	}

	known := request("POST", "/signin", body, origin, nil)

	unknown := request(
		"POST",
		"/signin",
		`{"email":"unknown@example.com","password":"wrong"}`,
		origin,
		nil,
	)
	if known.Code != 401 || known.Body.String() != unknown.Body.String() {
		t.Fatal("public signin enumeration")
	}

	for _, email := range []string{"alice@example.com", "unknown@example.com"} {
		w := request("POST", "/recovery", `{"email":"`+email+`"}`, origin, nil)
		if w.Code != 202 || w.Body.String() != enrolled.Body.String() {
			t.Fatal("public recovery enumeration")
		}
	}

	verifyBody, _ := json.Marshal(struct {
		Token string `json:"token"`
	}{verification})
	if w := request(
		"POST",
		"/verify",
		string(verifyBody),
		origin,
		nil,
	); w.Code != 200 {
		t.Fatal("verify", w.Code)
	}

	signedIn := request("POST", "/signin", body, origin, nil)
	if signedIn.Code != 200 {
		t.Fatal("signin", signedIn.Code)
	}

	cookies := signedIn.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("cookie missing")
	}

	cookie := cookies[0]
	if cookie.Name != httpauth.CookieName || !cookie.Secure ||
		!cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteLaxMode ||
		cookie.Domain != "" ||
		cookie.Path != "/" {
		t.Fatal("insecure cookie")
	}

	if strings.Contains(signedIn.Body.String(), cookie.Value) {
		t.Fatal("session in JSON")
	}

	if w := request("POST", "/logout", "", origin, cookie); w.Code != 200 {
		t.Fatal("logout", w.Code)
	}

	if _, err := s.Sessions().
		Authenticate(context.Background(), cookie.Value); err == nil {
		t.Fatal("logout did not revoke")
	}

	if ingressCalls == 0 {
		t.Fatal("ingress not applied")
	}

	if _, err := passwordhttp.New(
		s,
		passwordhttp.Config{},
	); err != password.ErrInvalidConfig {
		t.Fatal("missing ingress accepted")
	}
}
