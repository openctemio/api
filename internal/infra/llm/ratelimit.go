package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// DefaultRateLimitMaxWait bounds how long a call parks waiting for a token.
// Without a bound, an over-subscribed limiter would turn a rate limit into an
// unbounded hang: an HTTP-triggered triage would hold its request goroutine
// for minutes instead of failing fast. Callers whose context deadline is
// shorter than this error out at the deadline, which is the common case.
const DefaultRateLimitMaxWait = 30 * time.Second

// rateLimitedProvider enforces a requests-per-minute ceiling in front of a
// Provider. It is the enforcement point for AI_RATE_LIMIT_RPM, which is
// advertised as a cost control: an LLM call that is not made costs nothing.
type rateLimitedProvider struct {
	Provider

	limiter *rate.Limiter
	rpm     int
	maxWait time.Duration
}

// newRateLimitedProvider wraps p so that Complete cannot exceed rpm calls per
// minute across everything sharing limiter. rpm <= 0 means "no limit" and the
// provider is returned unwrapped.
func newRateLimitedProvider(p Provider, limiter *rate.Limiter, rpm int, maxWait time.Duration) Provider {
	if p == nil || limiter == nil || rpm <= 0 {
		return p
	}
	if maxWait <= 0 {
		maxWait = DefaultRateLimitMaxWait
	}
	return &rateLimitedProvider{Provider: p, limiter: limiter, rpm: rpm, maxWait: maxWait}
}

// Complete blocks until the shared limiter grants a token, then delegates.
// If no token becomes available within maxWait (or before the caller's context
// deadline), it returns ErrRateLimited without calling the provider — the
// caller's cost ceiling is the point, so failing is correct.
func (p *rateLimitedProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	waitCtx, cancel := context.WithTimeout(ctx, p.maxWait)
	defer cancel()

	if err := p.limiter.Wait(waitCtx); err != nil {
		return nil, fmt.Errorf("%w: local cap of %d requests/minute (AI_RATE_LIMIT_RPM): %v",
			ErrRateLimited, p.rpm, err)
	}
	return p.Provider.Complete(ctx, req)
}

// newRPMLimiter builds a limiter for rpm requests per minute. Burst is the
// full minute's allowance so a batch of triage jobs starting together is not
// serialized to one call every 60/rpm seconds; sustained throughput is still
// capped at rpm.
func newRPMLimiter(rpm int) *rate.Limiter {
	if rpm <= 0 {
		return nil
	}
	return rate.NewLimiter(rate.Limit(float64(rpm)/60.0), rpm)
}

// limiterRegistry hands out one limiter per credential scope, keyed so that
// every caller spending the same API key shares one budget. Platform-mode
// tenants share the platform key and therefore share the cap; a BYOK tenant
// pays its own bill and gets its own.
type limiterRegistry struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

func newLimiterRegistry() *limiterRegistry {
	return &limiterRegistry{limiters: make(map[string]*rate.Limiter)}
}

// get returns the limiter for scope, creating it on first use.
func (r *limiterRegistry) get(scope string, rpm int) *rate.Limiter {
	if rpm <= 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if l, ok := r.limiters[scope]; ok {
		return l
	}
	l := newRPMLimiter(rpm)
	r.limiters[scope] = l
	return l
}

// credentialScope derives a stable, non-reversible key for an API key so that
// limiters can be shared per credential without ever holding the secret in a
// map key that might be logged or dumped.
func credentialScope(prefix, apiKey string) string {
	if apiKey == "" {
		return prefix
	}
	sum := sha256.Sum256([]byte(apiKey))
	return prefix + ":" + hex.EncodeToString(sum[:8])
}
