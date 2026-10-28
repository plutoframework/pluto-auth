package local_test

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/plutoframework/pluto-auth/methods/password"
)

// recorder is test-only and bounded. Never use a recording/no-op sender as
// production email delivery; messages contain raw sensitive challenges.
type recorder struct {
	mu       sync.Mutex
	messages []password.Notification
}

func (r *recorder) Send(ctx context.Context, n password.Notification) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.messages) >= 4 {
		return errors.New("test recorder full")
	}

	r.messages = append(r.messages, n)

	return nil
}

func Example() {
	sender := &recorder{}
	// Synthetic material only; no email/network delivery or real credentials.
	err := sender.Send(context.Background(), password.Notification{
		Email: "synthetic@example.invalid", Purpose: password.VerifyEmail,
		Token: "synthetic-in-process-placeholder",
	})
	fmt.Println(err == nil, len(sender.messages))

	// Output: true 1
}
