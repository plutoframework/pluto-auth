// Package totp implements native second factors, not primary authentication.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Match implements RFC 6238 SHA-1, six digits, 30-second steps, with a fixed
// +/- one-step window. last is the highest previously accepted counter.
// Accepting a future step intentionally blocks earlier steps until time catches up.
func Match(seed []byte, code string, now time.Time, last int64) (int64, bool) {
	if len(seed) != 20 || len(code) != 6 || now.Unix() < 30 {
		return 0, false
	}

	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}

	counter := now.Unix() / 30
	matched := int64(-1)

	for step := counter - 1; step <= counter+1; step++ {
		expected := hotp(seed, step)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 &&
			step > last {
			matched = step
		}
	}

	return matched, matched >= 0
}

func hotp(seed []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))

	mac := hmac.New(sha1.New, seed)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	return fmt.Sprintf("%06d", value%1000000)
}

func provisioning(seed []byte, issuer, label string) string {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).
		EncodeToString(seed)
	values := url.Values{
		"secret":    {secret},
		"issuer":    {issuer},
		"algorithm": {"SHA1"},
		"digits":    {"6"},
		"period":    {"30"},
	}

	return "otpauth://totp/" + url.PathEscape(
		issuer+":"+strings.TrimSpace(label),
	) + "?" + values.Encode()
}
