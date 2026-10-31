// Package password provides bounded Argon2id hashing and password sign-in.
// Hash encoding and verification are adapted from Limen's credential-password
// plugin at a691ec98. See LICENSE and docs/PROVENANCE.md in the repository root.
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash    = errors.New("password: invalid or unsupported hash")
	ErrInvalidConfig  = errors.New("password: invalid configuration")
	ErrPasswordLength = errors.New("password: password length outside bounds")
)

const MaxPasswordBytes = 1024

type Config struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8

	// MaxConcurrent bounds simultaneous Argon2 computations per Hasher.
	// Request rate limits are separately required by Authenticator.
	MaxConcurrent int
}

func DefaultConfig() Config {
	return Config{
		MemoryKiB:     64 * 1024,
		Iterations:    3,
		Parallelism:   4,
		MaxConcurrent: 1,
	}
}

type Hasher struct {
	config Config
	slots  chan struct{}
}

func NewHasher(config Config) (*Hasher, error) {
	if !validCosts(config.MemoryKiB, config.Iterations, config.Parallelism) ||
		config.MaxConcurrent < 1 || config.MaxConcurrent > 64 {
		return nil, ErrInvalidConfig
	}

	return &Hasher{
		config: config,
		slots:  make(chan struct{}, config.MaxConcurrent),
	}, nil
}

func validCosts(memory, iterations uint32, parallel uint8) bool {
	return memory >= 19*1024 && memory <= 256*1024 &&
		iterations >= 2 && iterations <= 6 &&
		parallel >= 1 && parallel <= 16
}

func (h *Hasher) Hash(ctx context.Context, password []byte) (string, error) {
	return h.hash(ctx, password, 16, 32)
}

func (h *Hasher) hash(ctx context.Context, password []byte,
	saltBytes int, keyBytes uint32,
) (string, error) {
	if len(password) == 0 || len(password) > MaxPasswordBytes {
		return "", ErrPasswordLength
	}

	if err := h.acquire(ctx); err != nil {
		return "", err
	}

	defer h.release()

	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: generate salt: %w", err)
	}

	config := h.config
	key := argon2.IDKey(password, salt, config.Iterations,
		config.MemoryKiB, config.Parallelism, keyBytes)

	if err := ctx.Err(); err != nil {
		return "", err
	}

	encoder := base64.RawStdEncoding

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		config.MemoryKiB, config.Iterations, config.Parallelism,
		encoder.EncodeToString(salt), encoder.EncodeToString(key)), nil
}

// Verify uses the encoded parameters, not the current hashing configuration.
// Invalid encodings and excessive costs are rejected before running Argon2.
// Cancellation interrupts queueing, but cannot preempt an active computation.
func (h *Hasher) Verify(
	ctx context.Context,
	password []byte,
	encoded string,
) (bool, error) {
	if len(password) == 0 || len(password) > MaxPasswordBytes {
		return false, ErrPasswordLength
	}

	parsed, err := parse(encoded)
	if err != nil {
		return false, err
	}

	if err := h.acquire(ctx); err != nil {
		return false, err
	}

	defer h.release()

	key := argon2.IDKey(password, parsed.salt, parsed.iterations,
		parsed.memory, parsed.parallel, uint32(len(parsed.key)))

	if err := ctx.Err(); err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare(key, parsed.key) == 1, nil
}

// NeedsRehash reports parameter differences, including stronger stored costs.
// For a migration use HashAtLeast, not Hash, to avoid downgrading those costs.
func (h *Hasher) NeedsRehash(encoded string) (bool, error) {
	parsed, err := parse(encoded)
	if err != nil {
		return false, err
	}

	return parsed.memory != h.config.MemoryKiB ||
		parsed.iterations != h.config.Iterations ||
		parsed.parallel != h.config.Parallelism ||
		len(parsed.salt) != 16 || len(parsed.key) != 32, nil
}

// HashAtLeast retains every encoded cost dimension during password replacement.
// It never rewrites an existing hash during sign-in.
func (h *Hasher) HashAtLeast(ctx context.Context, value []byte,
	encoded string,
) (string, error) {
	info, err := parse(encoded)
	if err != nil {
		return "", err
	}

	config := h.config
	config.MemoryKiB = max(config.MemoryKiB, info.memory)
	config.Iterations = max(config.Iterations, info.iterations)
	config.Parallelism = max(config.Parallelism, info.parallel)
	stronger := &Hasher{config: config, slots: h.slots}

	return stronger.hash(ctx, value, max(16, len(info.salt)),
		uint32(max(32, len(info.key))))
}

func (h *Hasher) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	select {
	case h.slots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			h.release()

			return err
		}

		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() {
	<-h.slots
}

type hashInfo struct {
	memory     uint32
	iterations uint32
	parallel   uint8
	salt       []byte
	key        []byte
}

func parse(encoded string) (hashInfo, error) {
	if len(encoded) > 256 {
		return hashInfo{}, ErrInvalidHash
	}

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" ||
		parts[1] != "argon2id" || parts[2] != "v=19" {
		return hashInfo{}, ErrInvalidHash
	}

	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return hashInfo{}, ErrInvalidHash
	}

	values := [3]uint64{}

	for i, prefix := range []string{"m=", "t=", "p="} {
		if !strings.HasPrefix(params[i], prefix) {
			return hashInfo{}, ErrInvalidHash
		}

		value, err := strconv.ParseUint(strings.TrimPrefix(params[i], prefix),
			10, 32)
		if err != nil || (i == 2 && value > 255) {
			return hashInfo{}, ErrInvalidHash
		}

		values[i] = value
	}

	info := hashInfo{
		memory:     uint32(values[0]),
		iterations: uint32(values[1]),
		parallel:   uint8(values[2]),
	}
	if !validCosts(info.memory, info.iterations, info.parallel) {
		return hashInfo{}, ErrInvalidHash
	}

	decoder := base64.RawStdEncoding.Strict()

	salt, err := decoder.DecodeString(parts[4])
	if err != nil || len(salt) < 16 || len(salt) > 32 {
		return hashInfo{}, ErrInvalidHash
	}

	key, err := decoder.DecodeString(parts[5])
	if err != nil || len(key) < 32 || len(key) > 64 {
		return hashInfo{}, ErrInvalidHash
	}

	info.salt = salt
	info.key = key

	return info, nil
}
