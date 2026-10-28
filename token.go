package auth

import (
	"crypto/sha256"
	"encoding/base64"
)

// TokenDigest accepts only canonical encodings of 32 random bytes.
// A fast digest is appropriate for random tokens, never for passwords.
func TokenDigest(token string) (Digest, error) {
	if len(token) != 43 {
		return Digest{}, ErrUnauthenticated
	}

	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 32 ||
		base64.RawURLEncoding.EncodeToString(decoded) != token {
		return Digest{}, ErrUnauthenticated
	}

	return sha256.Sum256(decoded), nil
}
