package netclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// counter and record are what a test server saw, safe to read from the test.
type counter struct{ n atomic.Int32 }

func (c *counter) add() int32 { return c.n.Add(1) }
func (c *counter) get() int32 { return c.n.Load() }
func (c *counter) reset()     { c.n.Store(0) }

type record struct {
	mu     sync.Mutex
	bodies []string
}

func (r *record) add(s string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bodies = append(r.bodies, s)
	return len(r.bodies)
}

func (r *record) get() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.bodies...)
}

// clock is a hand-advanced clock: timers fire only when Advance passes their deadline,
// and Sleep moves time forward without waiting.
type clock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
	slept  []time.Duration
}

type fakeTimer struct {
	c        *clock
	deadline time.Time
	active   bool
	f        func()
}

func (t *fakeTimer) Reset(d time.Duration) bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := t.active
	t.deadline, t.active = t.c.now.Add(d), true
	return was
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := t.active
	t.active = false
	return was
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *clock) AfterFunc(d time.Duration, f func()) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, deadline: c.now.Add(d), active: true, f: f}
	c.timers = append(c.timers, t)
	return t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []func()
	for _, t := range c.timers {
		if t.active && !c.now.Before(t.deadline) {
			t.active = false
			due = append(due, t.f)
		}
	}
	c.mu.Unlock()
	for _, f := range due {
		f()
	}
}

func (c *clock) Sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	c.slept = append(c.slept, d)
	c.mu.Unlock()
	c.Advance(d)
	return nil
}

func testClient(c *clock, stderr io.Writer, o Options) *http.Client {
	o.IdleTimeout = time.Minute
	o.RetryBudget = 10 * time.Minute
	o.Stderr = stderr
	o.Now, o.Sleep, o.AfterFunc = c.Now, c.Sleep, c.AfterFunc
	o.Jitter = func(d time.Duration) time.Duration { return d }
	return New(o)
}

// chunkServer sends one chunk of its body each time the test asks, holding the response
// open in between.
func chunkServer(t *testing.T) (*httptest.Server, chan<- string) {
	chunks := make(chan string)
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		for {
			select {
			case chunk, ok := <-chunks:
				if !ok {
					return
				}
				io.WriteString(w, chunk)
				w.(http.Flusher).Flush()
			case <-done:
				return
			case <-r.Context().Done():
				return
			}
		}
	}))
	t.Cleanup(func() { close(done); srv.Close() })
	return srv, chunks
}

func TestABodyThatStallsFailsAfterTheIdleDeadline(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	srv, chunks := chunkServer(t)
	res, err := testClient(c, io.Discard, Options{}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	chunks <- "first"
	buf := make([]byte, 5)
	if _, err := io.ReadFull(res.Body, buf); err != nil {
		t.Fatal(err)
	}
	c.Advance(59 * time.Second)
	c.Advance(time.Second) // a full minute with no byte
	_, err = res.Body.Read(buf)
	var stall *StallError
	if !errors.As(err, &stall) || !strings.Contains(err.Error(), "no data for 1m0s") {
		t.Fatalf("got %v", err)
	}
}

func TestASlowButMovingBodySucceeds(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	srv, chunks := chunkServer(t)
	res, err := testClient(c, io.Discard, Options{}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var got bytes.Buffer
	for i := 0; i < 10; i++ { // ten chunks 50 s apart: over eight minutes in all
		c.Advance(50 * time.Second)
		chunks <- "chunk"
		buf := make([]byte, 5)
		if _, err := io.ReadFull(res.Body, buf); err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		got.Write(buf)
	}
	close(chunks)
	if rest, err := io.ReadAll(res.Body); err != nil || len(rest) != 0 || got.Len() != 50 {
		t.Fatalf("%q, %v, %d", rest, err, got.Len())
	}
}

func TestA503ThenA200SucceedsWithARetryLine(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	var calls counter
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.add() == 1 {
			w.WriteHeader(503)
			return
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	var stderr bytes.Buffer
	res, err := testClient(c, &stderr, Options{}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	want := "slow link to " + host + ": HTTP 503, retrying (1) in 500ms\n"
	if res.StatusCode != 200 || string(body) != "ok" || calls.get() != 2 || stderr.String() != want {
		t.Fatalf("status %d body %q calls %d stderr %q", res.StatusCode, body, calls.get(), stderr.String())
	}
}

func TestAPostIsNotResentAfterItsHeadersWereSent(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	var calls counter
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.add()
		io.ReadAll(r.Body)
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close() // delivered, then the connection drops with no answer
	}))
	defer srv.Close()
	var stderr bytes.Buffer
	_, err := testClient(c, &stderr, Options{}).Post(srv.URL, "application/json", strings.NewReader(`{"comment":"x"}`))
	if err == nil || calls.get() != 1 || stderr.Len() != 0 {
		t.Fatalf("err %v, calls %d, stderr %q", err, calls.get(), stderr.String())
	}
	// The same failure on a GET is retried.
	calls.reset()
	_, err = testClient(c, &stderr, Options{RetryBudget: time.Second}).Get(srv.URL)
	if err == nil || calls.get() < 2 || !strings.Contains(stderr.String(), "retrying (1)") {
		t.Fatalf("err %v, calls %d, stderr %q", err, calls.get(), stderr.String())
	}
}

func TestAPostIsNotResentOnA503(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	var calls counter
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.add()
		w.WriteHeader(503)
	}))
	defer srv.Close()
	res, err := testClient(c, io.Discard, Options{}).Post(srv.URL, "text/plain", strings.NewReader("x"))
	if err != nil || res.StatusCode != 503 || calls.get() != 1 {
		t.Fatalf("%v, %v, %d", res, err, calls.get())
	}
	res.Body.Close()
}

func TestARetrySafePostIsResentWithItsBody(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	var seen record
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if seen.add(string(b)) == 1 {
			w.WriteHeader(502)
		}
	}))
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL, strings.NewReader("grant"))
	res, err := testClient(c, io.Discard, Options{}).Do(RetrySafe(req))
	if err != nil || res.StatusCode != 200 || len(seen.get()) != 2 || seen.get()[1] != "grant" {
		t.Fatalf("%v, %v, %q", res, err, seen.get())
	}
	res.Body.Close()
}

// dialFails fails its first n round trips the way a refused or timed-out connect does,
// before any byte is written, then hands requests to next.
type dialFails struct {
	n    int
	next http.RoundTripper
}

func (d *dialFails) RoundTrip(r *http.Request) (*http.Response, error) {
	if d.n > 0 {
		d.n--
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connectex: connection refused")}
	}
	return d.next.RoundTrip(r)
}

func TestAPostIsResentWhenItFailedBeforeAnyByteWasSent(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	var seen record
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen.add(string(b))
	}))
	defer srv.Close()
	var stderr bytes.Buffer
	base := &dialFails{n: 2, next: http.DefaultTransport}
	res, err := testClient(c, &stderr, Options{Base: base}).Post(srv.URL, "text/plain", strings.NewReader("comment"))
	if err != nil || res.StatusCode != 200 || len(seen.get()) != 1 || seen.get()[0] != "comment" {
		t.Fatalf("%v, %v, %q", res, err, seen.get())
	}
	res.Body.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	want := "slow link to " + host + ": dial: connectex: connection refused, retrying (1) in 500ms\n" +
		"slow link to " + host + ": dial: connectex: connection refused, retrying (2) in 1s\n"
	if stderr.String() != want {
		t.Fatalf("stderr %q", stderr.String())
	}
}

func TestBackoffIsCappedAndGivesUpNamingTheHostAndTime(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	base := &dialFails{n: 1 << 30}
	req, _ := http.NewRequest("GET", "https://openproject.example/api/v3/x", nil)
	_, err := testClient(c, io.Discard, Options{Base: base}).Do(req)
	var giveUp *GiveUpError
	if !errors.As(err, &giveUp) || !strings.Contains(err.Error(), "slow link to openproject.example: gave up after") {
		t.Fatalf("got %v", err)
	}
	if giveUp.Tried > 10*time.Minute || giveUp.Tried < 9*time.Minute {
		t.Fatalf("tried for %s", giveUp.Tried)
	}
	for _, d := range c.slept {
		if d > MaxDelay {
			t.Fatalf("slept %s", d)
		}
	}
	if c.slept[0] != BaseDelay || c.slept[len(c.slept)-1] != MaxDelay {
		t.Fatalf("delays %v", c.slept)
	}
}

func TestRedirectsFollowTheCallersPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/end", http.StatusFound)
			return
		}
		io.WriteString(w, "followed")
	}))
	defer srv.Close()
	c := &clock{now: time.Unix(0, 0)}
	stay := testClient(c, io.Discard, Options{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
	res, err := stay.Get(srv.URL + "/start")
	if err != nil || res.StatusCode != http.StatusFound {
		t.Fatalf("%v, %v", res, err)
	}
	res.Body.Close()
	follow := testClient(c, io.Discard, Options{})
	res, err = follow.Get(srv.URL + "/start")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("%v, %v", res, err)
	}
	res.Body.Close()
}

func TestTheClientHasNoTotalTimeout(t *testing.T) {
	cl := New(Options{})
	tr := cl.Transport.(*transport).o.Base.(*http.Transport)
	if cl.Timeout != 0 || tr.ResponseHeaderTimeout != HeaderTimeout || tr.TLSHandshakeTimeout != DialTimeout {
		t.Fatalf("timeout %v, headers %v, TLS %v", cl.Timeout, tr.ResponseHeaderTimeout, tr.TLSHandshakeTimeout)
	}
}

func TestACertificateFailureIsNotRetried(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	var stderr bytes.Buffer
	c := &clock{now: time.Unix(0, 0)}
	if _, err := testClient(c, &stderr, Options{}).Get(srv.URL); err == nil || stderr.Len() != 0 {
		t.Fatalf("%v, %q", err, stderr.String())
	}
}
