// Package guard enforces scope, rate limits and concurrency caps on the way to
// the network. No other module is given a raw network handle; they all call
// through here.
package guard

import (
	"context"
	"sync"

	"golang.org/x/time/rate"

	"github.com/masagent/scopeguard/internal/scope"
)

// Throttle applies per-host token-bucket rate limiting plus per-host and global
// concurrency caps. Conservative defaults come from the scope's Limits.
type Throttle struct {
	limits scope.Limits

	mu        sync.Mutex
	perHost   map[string]*rate.Limiter
	hostSlots map[string]chan struct{}
	global    chan struct{}
}

func NewThrottle(l scope.Limits) *Throttle {
	return &Throttle{
		limits:    l,
		perHost:   map[string]*rate.Limiter{},
		hostSlots: map[string]chan struct{}{},
		global:    make(chan struct{}, l.MaxConcurrentTotal),
	}
}

func (t *Throttle) limiterFor(host string) *rate.Limiter {
	t.mu.Lock()
	defer t.mu.Unlock()
	l, ok := t.perHost[host]
	if !ok {
		l = rate.NewLimiter(rate.Limit(t.limits.RequestsPerSecondPerHost), t.limits.Burst)
		t.perHost[host] = l
	}
	return l
}

func (t *Throttle) slotsFor(host string) chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.hostSlots[host]
	if !ok {
		c = make(chan struct{}, t.limits.MaxConcurrentPerHost)
		t.hostSlots[host] = c
	}
	return c
}

// Acquire blocks until it is permissible to make one request to host, honouring
// the rate limit and both concurrency caps, or until ctx is cancelled. The
// returned release func MUST be called when the request completes.
func (t *Throttle) Acquire(ctx context.Context, host string) (release func(), err error) {
	// global concurrency
	select {
	case t.global <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// per-host concurrency
	hs := t.slotsFor(host)
	select {
	case hs <- struct{}{}:
	case <-ctx.Done():
		<-t.global
		return nil, ctx.Err()
	}
	// per-host rate
	if err := t.limiterFor(host).Wait(ctx); err != nil {
		<-hs
		<-t.global
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			<-hs
			<-t.global
		})
	}, nil
}
