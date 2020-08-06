package chanio

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestReadOnce(t *testing.T) {
	t.Run("okay", func(t *testing.T) {
		b := bytes.NewBufferString("message")
		got := ReadOnce(b)
		// Absolute timeout. Should never be reached.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		select {
		case <-got:
			// success
		case <-ctx.Done():
			t.Errorf("ReadOnce() = context should never timeout")
		}
	})
}
