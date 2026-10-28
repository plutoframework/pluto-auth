package password

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"unicode/utf8"

	auth "github.com/plutoframework/pluto-auth"
)

// CanonicalEmail deliberately supports ASCII dot-atom mailboxes and DNS domains
// only. Both parts are case-folded by application policy. No whitespace,
// display names, quoted locals, literals, SMTPUTF8, IDNA conversion or provider
// alias rewriting is performed. Applications must use this policy consistently.
func CanonicalEmail(input string) (string, error) {
	if len(input) > 254 || len(input) < 3 {
		return "", ErrInvalidEmail
	}

	local, domain, ok := strings.Cut(input, "@")
	if !ok || len(local) == 0 || len(local) > 64 ||
		strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") ||
		strings.Contains(local, "..") {
		return "", ErrInvalidEmail
	}

	for _, c := range local {
		if !asciiAlphaNumeric(c) &&
			!strings.ContainsRune(".!#$%&'*+-/=?^_`{|}~", c) {
			return "", ErrInvalidEmail
		}
	}

	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "", ErrInvalidEmail
	}

	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' ||
			label[len(label)-1] == '-' {
			return "", ErrInvalidEmail
		}

		for _, c := range label {
			if !asciiAlphaNumeric(c) && c != '-' {
				return "", ErrInvalidEmail
			}
		}
	}

	return strings.ToLower(input), nil
}

func asciiAlphaNumeric(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9'
}

func (s *Service) checkPassword(ctx context.Context, value []byte) error {
	if len(value) > MaxPasswordBytes || !utf8.Valid(value) ||
		utf8.RuneCount(value) < 15 {
		return ErrPasswordPolicy
	}

	if s.config.Policy != nil {
		if err := s.config.Policy.Check(ctx, value); err != nil {
			return ErrPasswordPolicy
		}
	}

	return ctx.Err()
}

func newChallenge(
	purpose Purpose,
	nowConfig LifecycleConfig,
) (string, Challenge, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", Challenge{}, err
	}

	token := base64.RawURLEncoding.EncodeToString(secret)

	digest, err := ChallengeDigest(purpose, token)
	if err != nil {
		return "", Challenge{}, err
	}

	now := nowConfig.Clock().UTC()

	ttl := nowConfig.VerificationTTL
	if purpose == RecoverPassword {
		ttl = nowConfig.RecoveryTTL
	}

	return token, Challenge{
		Digest: digest, Purpose: purpose,
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	}, nil
}

// ChallengeDigest validates canonical token encoding and separates purposes.
func ChallengeDigest(purpose Purpose, token string) (auth.Digest, error) {
	if purpose != VerifyEmail && purpose != RecoverPassword {
		return auth.Digest{}, ErrInvalidChallenge
	}

	if _, err := auth.TokenDigest(token); err != nil {
		return auth.Digest{}, ErrInvalidChallenge
	}

	return sha256.Sum256([]byte(string(purpose) + "\x00" + token)), nil
}
