package passwordhttp

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStrictBoundedDecode(t *testing.T) {
	for _, body := range []string{
		`{"email":"a@example.com"} {}`,
		`{"email":"a@example.com","role":"admin"}`,
		`{"email":"a@example.com","email":"b@example.com"}`,
		`{"email":"a@example.com","EMAIL":"b@example.com"}`,
		`{"email":"a` + string([]byte{0xff}) + `@example.com"}`, `null`, `[]`, `{"email":12}`, `{"email":"` + strings.Repeat("a", 8192) + `"}`,
	} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()

		var target emailInput
		if decode(w, r, &target) || w.Code != 400 {
			t.Fatal("accepted ambiguous or excessive input")
		}
	}

	r := httptest.NewRequest(
		"POST",
		"/",
		strings.NewReader(`{"email":"a@example.com"}`),
	)
	r.Header.Set("Content-Type", "application/json; charset=utf-8")

	w := httptest.NewRecorder()

	var target emailInput
	if !decode(w, r, &target) || target.Email != "a@example.com" {
		t.Fatal("valid JSON rejected")
	}

	r.Header.Set("Content-Type", "text/plain")

	if decode(httptest.NewRecorder(), r, &target) {
		t.Fatal("accepted wrong content type")
	}
}

func FuzzBoundedJSON(f *testing.F) {
	f.Add(`{"email":"a@example.com"}`)
	f.Fuzz(func(t *testing.T, body string) {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")

		var input resetInput
		decode(httptest.NewRecorder(), r, &input)
	})
}
