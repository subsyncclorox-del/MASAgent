package guard

import (
	"context"
	"testing"
	"time"

	"github.com/masagent/scopeguard/internal/scope"
)

func TestPerHostConcurrencyCap(t *testing.T) {
	l := scope.DefaultLimits()
	l.MaxConcurrentPerHost = 2
	l.MaxConcurrentTotal = 10
	l.RequestsPerSecondPerHost = 1000
	l.Burst = 1000
	th := NewThrottle(l)

	ctx := context.Background()
	r1, err := th.Acquire(ctx, "h")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := th.Acquire(ctx, "h")
	if err != nil {
		t.Fatal(err)
	}
	// Third acquire for same host must block until one releases.
	done := make(chan struct{})
	go func() {
		r3, _ := th.Acquire(ctx, "h")
		if r3 != nil {
			r3()
		}
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("third acquire should have blocked while 2 held")
	case <-time.After(50 * time.Millisecond):
	}
	r1()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("third acquire should proceed after release")
	}
	r2()
}

func TestAcquireRespectsContext(t *testing.T) {
	l := scope.DefaultLimits()
	l.MaxConcurrentTotal = 1
	th := NewThrottle(l)
	hold, _ := th.Acquire(context.Background(), "a")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := th.Acquire(ctx, "b"); err == nil {
		t.Fatal("expected context deadline error when global cap saturated")
	}
	hold()
}
