package password

import (
	"context"
	"sync"
	"time"
)

// WindowLimiter is bounded single-process protection for tests/development or
// a single replica. Multiple replicas require an application-supplied shared
// limiter. At capacity, new keys fail closed; active entries are never evicted.
type WindowLimiter struct {
	mu       sync.Mutex
	entries  map[string]windowEntry
	capacity int
	attempts int
	window   time.Duration
	clock    func() time.Time
}

type windowEntry struct {
	expires time.Time
	count   int
}

func NewWindowLimiter(capacity, attempts int, window time.Duration,
	clock func() time.Time,
) (*WindowLimiter, error) {
	if capacity < 1 || capacity > 1_000_000 || attempts < 1 ||
		window <= 0 || clock == nil {
		return nil, ErrInvalidConfig
	}

	return &WindowLimiter{
		entries: make(map[string]windowEntry), capacity: capacity,
		attempts: attempts, window: window, clock: clock,
	}, nil
}

func (l *WindowLimiter) Allow(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if len(key) == 0 || len(key) > 256 {
		return ErrLimited
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	now := l.clock()

	entry, exists := l.entries[key]
	if exists && !now.Before(entry.expires) {
		exists = false
	}

	if !exists {
		if len(l.entries) >= l.capacity {
			for candidate, record := range l.entries {
				if !now.Before(record.expires) {
					delete(l.entries, candidate)
				}
			}

			if len(l.entries) >= l.capacity {
				return ErrLimited
			}
		}

		entry = windowEntry{expires: now.Add(l.window)}
	}

	if entry.count >= l.attempts {
		return ErrLimited
	}

	entry.count++
	l.entries[key] = entry

	return nil
}
