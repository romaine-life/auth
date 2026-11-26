// Package netclient is the HTTP client every romaine-auth call to a remote service uses.
// It is built for slow, lossy links (a hotel Wi-Fi at 250 ms and 10-40% loss with the
// tunnel home still up) rather than a fixed total-duration cap, which turns a slow answer
// into "the service is down":
//
//   - There is no total-duration cap. Connection setup (dial, TLS) and the wait for the
//     response headers are bounded, and a response body fails only when no byte of it
//     has arrived for the idle deadline, however long the whole body takes.
//   - Transient failures (dial errors, timeouts, connection resets, HTTP 502/503/504) are
//     retried with capped exponential backoff and jitter, for a bounded total, and each
//     retry says so on stderr: "slow link to <host>: <short error>, retrying (n) in <d>".
//   - A request is resent only when that cannot repeat an action: a failure before any
//     byte of the request was written is resent whatever the method; a failure after that
//     is resent only for an idempotent method or a request marked with RetrySafe, and only
//     when its body can be replayed.
//
// The client's CheckRedirect is the caller's, so each client keeps its redirect policy.
package netclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"sync"
	"time"
)

// Defaults for New. Options override them, which tests use to run in milliseconds.
const (
	DialTimeout   = 30 * time.Second // TCP connect, and separately the TLS handshake
	HeaderTimeout = 60 * time.Second // from the request written to the response headers
	IdleTimeout   = 60 * time.Second // a response body with no byte arriving for this long
	RetryBudget   = 10 * time.Minute // total time spent on one request before giving up
	BaseDelay     = 500 * time.Millisecond
	MaxDelay      = 30 * time.Second
)

// Timer is the part of *time.Timer the body's idle deadline uses; tests substitute a
// clock they advance by hand.
type Timer interface {
	Reset(time.Duration) bool
	Stop() bool
}

// Options adjusts a client. The zero value is the production client.
type Options struct {
	// CheckRedirect is the http.Client's redirect policy; nil follows redirects.
	CheckRedirect func(*http.Request, []*http.Request) error

	DialTimeout, HeaderTimeout, IdleTimeout, RetryBudget, BaseDelay, MaxDelay time.Duration

	// Base is the transport requests go through; nil is a clone of http.DefaultTransport
	// with the dial, TLS and header timeouts above.
	Base http.RoundTripper
	// Stderr receives the retry lines; nil is os.Stderr.
	Stderr io.Writer
	// Now, Sleep, Jitter and AfterFunc replace the clock in tests.
	Now       func() time.Time
	Sleep     func(context.Context, time.Duration) error
	Jitter    func(time.Duration) time.Duration
	AfterFunc func(time.Duration, func()) Timer
}

// New returns a client with no total timeout whose transport bounds connection setup,
// the wait for headers and body stalls, and retries transient failures.
func New(o Options) *http.Client {
	if o.DialTimeout == 0 {
		o.DialTimeout = DialTimeout
	}
	if o.HeaderTimeout == 0 {
		o.HeaderTimeout = HeaderTimeout
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = IdleTimeout
	}
	if o.RetryBudget == 0 {
		o.RetryBudget = RetryBudget
	}
	if o.BaseDelay == 0 {
		o.BaseDelay = BaseDelay
	}
	if o.MaxDelay == 0 {
		o.MaxDelay = MaxDelay
	}
	if o.Base == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.DialContext = (&net.Dialer{Timeout: o.DialTimeout, KeepAlive: 30 * time.Second}).DialContext
		t.TLSHandshakeTimeout = o.DialTimeout
		t.ResponseHeaderTimeout = o.HeaderTimeout
		o.Base = t
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleep
	}
	if o.Jitter == nil {
		// Full jitter in the upper half: between d/2 and d.
		o.Jitter = func(d time.Duration) time.Duration { return d/2 + rand.N(d/2+1) }
	}
	if o.AfterFunc == nil {
		o.AfterFunc = func(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }
	}
	return &http.Client{Transport: &transport{o: o}, CheckRedirect: o.CheckRedirect}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type retrySafeKey struct{}

// RetrySafe marks a request whose repeat does no harm even if the server already acted
// on it (such as an OAuth client-credentials grant, which only issues another token), so
// a POST or PATCH may be resent after it was written. Its body must be replayable, as a
// body from bytes.Reader, bytes.Buffer or strings.Reader is.
func RetrySafe(req *http.Request) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), retrySafeKey{}, true))
}

func idempotent(req *http.Request) bool {
	switch req.Method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete,
		"LIST": // OpenBao's read of a path's keys
		return true
	}
	safe, _ := req.Context().Value(retrySafeKey{}).(bool)
	return safe
}

func hasBody(req *http.Request) bool { return req.Body != nil && req.Body != http.NoBody }

type transport struct{ o Options }

// StallError is a response body that stopped arriving.
type StallError struct {
	Host string
	Idle time.Duration
}

func (e *StallError) Error() string {
	return fmt.Sprintf("slow link to %s: no data for %s, gave up", e.Host, e.Idle)
}
func (e *StallError) Timeout() bool { return true }

// GiveUpError is a request that kept failing for the whole retry budget, or failed in a
// way it can't safely be resent after; Err is the last failure.
type GiveUpError struct {
	Host     string
	Attempts int
	Tried    time.Duration
	Err      error
}

func (e *GiveUpError) Error() string {
	return fmt.Sprintf("slow link to %s: gave up after %d attempts over %s: %v", e.Host, e.Attempts, e.Tried.Round(time.Second), e.Err)
}
func (e *GiveUpError) Unwrap() error { return e.Err }

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	o := t.o
	host := req.URL.Host
	start := o.Now()
	delay := o.BaseDelay
	for attempt := 1; ; attempt++ {
		// A RoundTripper must not modify the caller's request, so a resend with a body
		// goes out as a copy carrying a fresh body.
		r := req
		if attempt > 1 && hasBody(req) {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			r = req.Clone(req.Context())
			r.Body = body
		}
		res, sent, err := t.once(r)
		var reason string
		switch {
		case err != nil:
			if req.Context().Err() != nil || !transient(err) {
				return nil, err
			}
			// Written or not, the request is resent only if that cannot repeat an action.
			if sent && !idempotent(req) {
				return nil, err
			}
			reason = shortError(err)
		case res.StatusCode == http.StatusBadGateway || res.StatusCode == http.StatusServiceUnavailable || res.StatusCode == http.StatusGatewayTimeout:
			if !idempotent(req) {
				return res, nil
			}
			reason = "HTTP " + fmt.Sprint(res.StatusCode)
			err = fmt.Errorf("HTTP %d %s", res.StatusCode, http.StatusText(res.StatusCode))
		default:
			return res, nil
		}
		if hasBody(req) && req.GetBody == nil {
			if res != nil {
				return res, nil
			}
			return nil, err
		}
		wait := o.Jitter(delay)
		tried := o.Now().Sub(start)
		if tried+wait > o.RetryBudget {
			if res != nil {
				res.Body.Close()
			}
			return nil, &GiveUpError{Host: host, Attempts: attempt, Tried: tried, Err: err}
		}
		if res != nil {
			io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
			res.Body.Close()
		}
		fmt.Fprintf(o.Stderr, "slow link to %s: %s, retrying (%d) in %s\n", host, reason, attempt, wait.Round(100*time.Millisecond))
		if err := o.Sleep(req.Context(), wait); err != nil {
			return nil, err
		}
		delay = min(delay*2, o.MaxDelay)
	}
}

// once sends one attempt. sent reports whether any byte of the request may have been
// written: a header field reaching the connection's writer counts, so it errs toward
// "sent". The response body gets the idle deadline.
func (t *transport) once(req *http.Request) (*http.Response, bool, error) {
	ctx, cancel := context.WithCancel(req.Context())
	var mu sync.Mutex
	sent := false
	mark := func() { mu.Lock(); sent = true; mu.Unlock() }
	trace := &httptrace.ClientTrace{
		WroteHeaderField: func(string, []string) { mark() },
		WroteHeaders:     mark,
		WroteRequest:     func(httptrace.WroteRequestInfo) { mark() },
	}
	res, err := t.o.Base.RoundTrip(req.Clone(httptrace.WithClientTrace(ctx, trace)))
	mu.Lock()
	wasSent := sent
	mu.Unlock()
	if err != nil {
		cancel()
		return nil, wasSent, err
	}
	res.Body = newIdleBody(res.Body, req.URL.Host, t.o, cancel)
	return res, wasSent, nil
}

// transient reports whether err is a network failure worth another attempt, as opposed to
// one that will fail the same way again (a certificate the client rejects, a name that
// doesn't exist, a malformed request).
func transient(err error) bool {
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var record tls.RecordHeaderError
	if errors.As(err, &cert) || errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid) || errors.As(err, &record) {
		return false
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return dns.IsTimeout || dns.IsTemporary
	}
	var timeout interface{ Timeout() bool }
	if errors.As(err, &timeout) && timeout.Timeout() {
		return true
	}
	var op *net.OpError
	if errors.As(err, &op) {
		return true // dial, read or write on the connection: refused, reset, aborted, unreachable
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		strings.Contains(err.Error(), "connection reset") || strings.Contains(err.Error(), "connection lost") ||
		strings.Contains(err.Error(), "server closed")
}

// shortError is err in a few words for the retry line.
func shortError(err error) string {
	var timeout interface{ Timeout() bool }
	if errors.As(err, &timeout) && timeout.Timeout() {
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			return "connect timed out"
		}
		if strings.Contains(err.Error(), "TLS handshake") {
			return "TLS handshake timed out"
		}
		if strings.Contains(err.Error(), "response headers") {
			return "no answer"
		}
		return "timed out"
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		inner := op.Err
		for {
			next := errors.Unwrap(inner)
			if next == nil {
				break
			}
			inner = next
		}
		return op.Op + ": " + inner.Error()
	}
	msg := err.Error()
	if len(msg) > 80 {
		msg = msg[:80] + "..."
	}
	return msg
}

// idleBody fails a read once no byte has arrived for the idle deadline, by cancelling the
// attempt's context; every read that returns data pushes the deadline back.
type idleBody struct {
	body   io.ReadCloser
	host   string
	idle   time.Duration
	cancel context.CancelFunc
	timer  Timer

	mu      sync.Mutex
	stalled bool
}

func newIdleBody(body io.ReadCloser, host string, o Options, cancel context.CancelFunc) *idleBody {
	b := &idleBody{body: body, host: host, idle: o.IdleTimeout, cancel: cancel}
	b.timer = o.AfterFunc(o.IdleTimeout, func() {
		b.mu.Lock()
		b.stalled = true
		b.mu.Unlock()
		cancel()
	})
	return b
}

func (b *idleBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	b.mu.Lock()
	stalled := b.stalled
	b.mu.Unlock()
	if stalled && err != nil && err != io.EOF {
		return n, &StallError{Host: b.host, Idle: b.idle}
	}
	if n > 0 && !stalled {
		b.timer.Reset(b.idle)
	}
	return n, err
}

func (b *idleBody) Close() error {
	b.timer.Stop()
	err := b.body.Close()
	b.cancel()
	return err
}
