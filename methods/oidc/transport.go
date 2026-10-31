package oidc

import (
	"errors"
	"io"
	"net/http"
)

type boundedTransport struct{ base http.RoundTripper }

func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.User != nil || r.URL.Hostname() == "" {
		return nil, ErrConfig
	}

	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}

	response, err := base.RoundTrip(r)
	if err != nil {
		return nil, err
	}

	response.Body = &boundedBody{ReadCloser: response.Body, remaining: 1 << 20}

	return response, nil
}

type boundedBody struct {
	io.ReadCloser
	remaining int
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, errors.New("oidc: response limit exceeded")
	}

	if len(p) > b.remaining {
		p = p[:b.remaining]
	}

	n, err := b.ReadCloser.Read(p)
	b.remaining -= n

	return n, err
}
