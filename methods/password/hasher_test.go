package password

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func testHasher(t *testing.T) *Hasher {
	t.Helper()

	hasher, err := NewHasher(Config{
		MemoryKiB:     19 * 1024,
		Iterations:    2,
		Parallelism:   1,
		MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	return hasher
}

// These cases preserve the upstream hasher's round-trip and PHC invariants.
func TestHashRoundTrip(t *testing.T) {
	hasher := testHasher(t)

	ctx := context.Background()
	for _, secret := range []string{
		"correct horse battery staple",
		"Pässwörd with spaces and Unicode ☄️",
		strings.Repeat("long password ", 60),
	} {
		encoded, err := hasher.Hash(ctx, []byte(secret))
		if err != nil {
			t.Fatal(err)
		}

		valid, err := hasher.Verify(ctx, []byte(secret), encoded)
		if err != nil || !valid {
			t.Fatalf("round trip: valid=%v, err=%v", valid, err)
		}

		valid, err = hasher.Verify(ctx, []byte("wrong password"), encoded)
		if err != nil || valid {
			t.Fatal("wrong password accepted")
		}

		second, err := hasher.Hash(ctx, []byte(secret))
		if err != nil || second == encoded {
			t.Fatal("hash salt is not independently random")
		}
	}
}

func TestEncodedParametersAndRehash(t *testing.T) {
	old := testHasher(t)

	current, err := NewHasher(Config{
		MemoryKiB:     32 * 1024,
		Iterations:    3,
		Parallelism:   2,
		MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	encoded, err := old.Hash(ctx, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}

	valid, err := current.Verify(ctx,
		[]byte("correct horse battery staple"), encoded)
	if err != nil || !valid {
		t.Fatalf("verification ignored encoded parameters: %v", err)
	}

	needed, err := current.NeedsRehash(encoded)
	if err != nil || !needed {
		t.Fatal("parameter migration not detected")
	}

	needed, err = old.NeedsRehash(encoded)
	if err != nil || needed {
		t.Fatal("unchanged parameters require rehash")
	}
}

func TestRejectMalformedCosts(t *testing.T) {
	suffix := "$AAAAAAAAAAAAAAAAAAAAAA$" + strings.Repeat("A", 43)
	for _, encoded := range []string{
		"", "garbage", strings.Repeat("A", 257),
		"$argon2i$v=19$m=19456,t=2,p=1" + suffix,
		"$argon2id$v=18$m=19456,t=2,p=1" + suffix,
		"$argon2id$v=19$m=0,t=2,p=1" + suffix,
		"$argon2id$v=19$m=4294967295,t=2,p=1" + suffix,
		"$argon2id$v=19$m=19456,t=0,p=1" + suffix,
		"$argon2id$v=19$m=19456,t=999,p=1" + suffix,
		"$argon2id$v=19$m=19456,t=2,p=0" + suffix,
		"$argon2id$v=19$m=19456,t=2,p=257" + suffix,
		"$argon2id$v=19$m=19456,t=2,p=1,p=1" + suffix,
		"$argon2id$v=19$m=19456,m=19456,p=1" + suffix,
		"$argon2id$v=19$m=19456,t=2,p=1$AA$AA",
	} {
		if _, err := parse(encoded); !errors.Is(err, ErrInvalidHash) {
			t.Fatalf("malformed hash accepted: %q", encoded)
		}
	}
}

func TestHashCancellationAndBounds(t *testing.T) {
	hasher := testHasher(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := hasher.Hash(
		ctx,
		[]byte("correct horse battery staple"),
	); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatal("canceled hash performed work")
	}

	if _, err := hasher.Hash(
		context.Background(),
		[]byte(
			strings.Repeat("A", MaxPasswordBytes+1),
		),
	); !errors.Is(err, ErrPasswordLength) {
		t.Fatal("unbounded password accepted")
	}

	// Occupy the sole computation slot and ensure queueing is cancellable.
	hasher.slots <- struct{}{}

	if err := hasher.acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled waiter acquired a slot")
	}

	hasher.release()
}

func FuzzPHCParser(f *testing.F) {
	f.Add("$argon2id$v=19$m=19456,t=2,p=1$" +
		"AAAAAAAAAAAAAAAAAAAAAA$" + strings.Repeat("A", 43))
	f.Add("")
	f.Add("$argon2id$v=19$m=4294967295,t=999,p=257$AA$AA")
	f.Fuzz(func(t *testing.T, encoded string) {
		info, err := parse(encoded)
		if err == nil &&
			(!validCosts(info.memory, info.iterations, info.parallel) ||
				len(info.salt) < 16 || len(info.key) < 32) {
			t.Fatal(
				"parser accepted costs or lengths outside verification bounds",
			)
		}
	})
}
