package totp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
)

// AESProtector is an explicit host-managed key ring. Load keys from the host's
// secret manager, never the credential database. Keep old keys during rotation;
// new setups use active. Existing ciphertext can be rewrapped by host tooling.
// This helper does not provision, persist, rotate or back up keys.
type AESProtector struct {
	active uint32
	keys   map[uint32]cipher.AEAD
}

func NewAESProtector(
	active uint32,
	keys map[uint32][]byte,
) (*AESProtector, error) {
	if active == 0 || len(keys) == 0 || len(keys) > 32 {
		return nil, ErrConfig
	}

	p := &AESProtector{
		active: active,
		keys:   make(map[uint32]cipher.AEAD, len(keys)),
	}
	for id, key := range keys {
		if id == 0 || len(key) != 32 {
			return nil, ErrConfig
		}

		nonzero := false
		for _, b := range key {
			nonzero = nonzero || b != 0
		}

		if !nonzero {
			return nil, ErrConfig
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, ErrConfig
		}

		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrConfig
		}

		p.keys[id] = aead
	}

	if p.keys[active] == nil {
		return nil, ErrConfig
	}

	return p, nil
}

func aad(
	subject string,
) []byte {
	return []byte("pluto-auth/totp/seed\x00" + subject)
}

func (p *AESProtector) Seal(
	ctx context.Context,
	subject string,
	seed []byte,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if subject == "" || len(seed) != 20 {
		return nil, ErrDenied
	}

	aead := p.keys[p.active]
	header := make([]byte, 4+aead.NonceSize())
	binary.BigEndian.PutUint32(header, p.active)

	_, _ = rand.Read(header[4:])

	return aead.Seal(header, header[4:], seed, aad(subject)), nil
}

func (p *AESProtector) Open(
	ctx context.Context,
	subject string,
	encrypted []byte,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(encrypted) < 4 {
		return nil, ErrDenied
	}

	aead := p.keys[binary.BigEndian.Uint32(encrypted[:4])]
	if aead == nil || len(encrypted) != 4+aead.NonceSize()+20+aead.Overhead() {
		return nil, ErrDenied
	}

	seed, err := aead.Open(
		nil,
		encrypted[4:4+aead.NonceSize()],
		encrypted[4+aead.NonceSize():],
		aad(subject),
	)
	if err != nil {
		return nil, ErrDenied
	}

	return seed, nil
}
