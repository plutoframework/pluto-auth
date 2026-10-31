package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type pending struct {
	sync.Mutex
	tx Transaction
}

func (p *pending) Save(_ context.Context, tx Transaction) error {
	p.Lock()
	defer p.Unlock()

	p.tx = tx

	return nil
}

func (p *pending) Consume(
	_ context.Context,
	s string,
	b [32]byte,
	n time.Time,
) (Transaction, error) {
	p.Lock()
	defer p.Unlock()

	if p.tx.State != s || p.tx.BrowserDigest != b || !n.Before(p.tx.Expires) {
		return Transaction{}, ErrDenied
	}

	tx := p.tx
	p.tx = Transaction{}

	return tx, nil
}

func TestCodeFlow(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, scenario := range []string{"valid", "nonce", "audience", "issuer", "expired", "azp", "signature", "binding", "browser", "expiry", "replay"} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Now().Truncate(time.Second)
			store := &pending{}

			var issuer, nonce, verifier string

			exchanges := 0

			server := httptest.NewTLSServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")

					switch r.URL.Path {
					case "/.well-known/openid-configuration":
						_ = json.NewEncoder(w).
							Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
					case "/keys":
						_ = json.NewEncoder(w).
							Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, Algorithm: "RS256", Use: "sig"}}})
					case "/token":
						exchanges++

						if err := r.ParseForm(); err != nil {
							t.Error(err)
						}

						if r.Form.Get("code_verifier") != verifier ||
							r.Form.Get(
								"redirect_uri",
							) != "https://app.example/callback" {
							t.Error("missing proof binding")
						}

						claims := map[string]any{
							"iss":   issuer,
							"sub":   "external-42",
							"aud":   "app",
							"exp":   now.Add(time.Minute).Unix(),
							"iat":   now.Unix(),
							"nonce": nonce,
						}

						switch scenario {
						case "nonce":
							claims["nonce"] = "wrong"
						case "audience":
							claims["aud"] = "other"
						case "issuer":
							claims["iss"] = "https://other.example"
						case "expired":
							claims["exp"] = now.Add(-time.Minute).Unix()
						case "azp":
							claims["aud"] = []string{"app", "other"}
						}

						payload, _ := json.Marshal(claims)

						signed, err := signer.Sign(payload)
						if err != nil {
							t.Error(err)

							return
						}

						if scenario == "signature" {
							payload = append(payload, ' ')

							other, keyErr := rsa.GenerateKey(rand.Reader, 2048)
							if keyErr != nil {
								t.Error(keyErr)

								return
							}

							untrusted, signErr := jose.NewSigner(
								jose.SigningKey{
									Algorithm: jose.RS256,
									Key:       other,
								},
								nil,
							)
							if signErr != nil {
								t.Error(signErr)

								return
							}

							signed, signErr = untrusted.Sign(payload)
							if signErr != nil {
								t.Error(signErr)

								return
							}
						}

						raw, err := signed.CompactSerialize()
						if err != nil {
							t.Error(err)

							return
						}

						_ = json.NewEncoder(w).
							Encode(map[string]any{"access_token": "private", "token_type": "Bearer", "id_token": raw})
					default:
						http.NotFound(w, r)
					}
				}),
			)
			defer server.Close()

			issuer = server.URL
			hc := server.Client()
			hc.Timeout = 5 * time.Second

			client, err := New(
				context.Background(),
				Config{
					Issuer:       issuer,
					ClientID:     "app",
					ClientSecret: "test-only",
					RedirectURL:  "https://app.example/callback",
					HTTPClient:   hc,
					Transactions: store,
					Clock:        func() time.Time { return now },
				},
			)
			if err != nil {
				t.Fatal(err)
			}

			binding := "server-browser-binding-01234567890123456789"

			location, err := client.Begin(context.Background(), binding)
			if err != nil {
				t.Fatal(err)
			}

			parsed, _ := url.Parse(location)
			q := parsed.Query()
			nonce = store.tx.Nonce
			verifier = store.tx.Verifier

			if q.Get("code_challenge_method") != "S256" ||
				q.Get("code_challenge") == "" ||
				q.Get("nonce") != nonce {
				t.Fatal("missing PKCE/nonce")
			}

			if scenario == "binding" {
				store.tx.Issuer = "https://other.example"
			}

			if scenario == "browser" {
				binding = "different-browser-binding-012345678901234"
			}

			if scenario == "expiry" {
				now = store.tx.Expires
			}

			identity, err := client.Complete(
				context.Background(),
				q.Get("state"),
				binding,
				"code",
			)
			if scenario == "valid" || scenario == "replay" {
				if err != nil || identity.Issuer() != issuer ||
					identity.Subject() != "external-42" {
					t.Fatalf("expected verified identity: %v", err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid proof")
			}

			if (scenario == "browser" || scenario == "expiry") &&
				exchanges != 0 {
				t.Fatal("exchanged without intent")
			}

			if scenario == "replay" {
				_, err = client.Complete(
					context.Background(),
					q.Get("state"),
					binding,
					"code",
				)
				if err == nil || exchanges != 1 {
					t.Fatal("replay")
				}
			}
		})
	}
}

func TestConsumeExactlyOnce(t *testing.T) {
	now := time.Now()
	p := &pending{tx: Transaction{State: "test", Expires: now.Add(time.Minute)}}

	var group sync.WaitGroup

	results := make(chan error, 16)

	for range 16 {
		group.Go(
			func() { _, err := p.Consume(context.Background(), "test", [32]byte{}, now); results <- err },
		)
	}

	group.Wait()
	close(results)

	successes := 0

	for err := range results {
		if err == nil {
			successes++
		}
	}

	if successes != 1 {
		t.Fatalf("consumed %d times", successes)
	}
}

func FuzzCallbackInput(f *testing.F) {
	f.Add("state", "browser", "code")
	f.Fuzz(func(t *testing.T, state, browser, code string) {
		c := &Client{clock: time.Now, transactions: &pending{}}

		_, err := c.Complete(context.Background(), state, browser, code)
		if err == nil {
			t.Fatal("unbound callback accepted")
		}
	})
}
