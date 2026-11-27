package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestBreakGlassRequestSendsSessionWithMachineToken(t *testing.T) {
	seen := azureFixture(t, `{"id":"bg_1","status":"pending","session":"s-1","minutes":60,"approveUrl":"https://auth.romaine.life/break-glass/bg_1","requestExpiresAt":1900000000}`)
	req, err := RequestBreakGlass(context.Background(), "move the runner keys", "s-1", 60)
	if err != nil || req.ID != "bg_1" || req.ApproveURL != "https://auth.romaine.life/break-glass/bg_1" || req.RequestExpiresAt != 1900000000 {
		t.Fatalf("got %+v, %v", req, err)
	}
	r := (*seen)[0]
	if r.Method != "POST" || r.URL.String() != BaseURL+"/api/break-glass/requests" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		t.Fatalf("sent %s %s", r.Method, r.URL)
	}
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	if body["reason"] != "move the runner keys" || body["session"] != "s-1" || body["minutes"] != float64(60) {
		t.Fatalf("body %v", body)
	}
}

func TestBreakGlassWaitAsksAgainUntilDecided(t *testing.T) {
	seen := azureFixture(t,
		`{"id":"bg_1","status":"pending"}`,
		`{"id":"bg_1","status":"denied","decidedBy":"nelson@romaine.life"}`)
	got, err := WaitBreakGlass(context.Background(), "bg_1")
	if err != nil || got.Status != "denied" || got.DecidedBy != "nelson@romaine.life" || len(*seen) != 2 {
		t.Fatalf("got %+v after %d calls, %v", got, len(*seen), err)
	}
	if u := (*seen)[0].URL; u.Path != "/api/break-glass/requests/bg_1" || u.Query().Get("wait") != "10" {
		t.Fatalf("asked %s", u)
	}
}

func TestSessionBreakGlassFindsOnlyThatSession(t *testing.T) {
	answer := `[{"id":"bg_1","session":"s-1","grantExpiresAt":100},{"id":"bg_2","session":"s-2","grantExpiresAt":300},{"id":"bg_3","session":"s-1","grantExpiresAt":200}]`
	seen := azureFixture(t, answer, answer)
	got, err := SessionBreakGlass(context.Background(), "s-1")
	if err != nil || got == nil || got.ID != "bg_3" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if (*seen)[0].URL.String() != BaseURL+"/api/break-glass/active" {
		t.Fatalf("asked %s", (*seen)[0].URL)
	}
	none, err := SessionBreakGlass(context.Background(), "s-9")
	if err != nil || none != nil {
		t.Fatalf("a session with no grant got %+v, %v", none, err)
	}
}

func TestClusterTokenAsksForTheBreakGlassAudience(t *testing.T) {
	fixture(t, 200, "")
	var audience string
	requestClient = &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		audience = body["audience"]
		return &http.Response{StatusCode: 200, Header: make(http.Header), Request: r,
			Body: io.NopCloser(strings.NewReader(`{"token":"tok","expires_at":1900000000,"device":"testpc","grant_id":"bg_1"}`))}, nil
	})}
	got, err := GetClusterToken(context.Background())
	if err != nil || got.Token != "tok" || got.GrantID != "bg_1" || audience != "home-cluster-break-glass" {
		t.Fatalf("got %+v with audience %q, %v", got, audience, err)
	}
}

func TestExecCredentialIsWhatKubectlReads(t *testing.T) {
	b, err := ExecCredential(ClusterToken{Token: "tok", ExpiresAt: 1900000000})
	want := `{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"expirationTimestamp":"2030-03-17T17:46:40Z","token":"tok"}}`
	if err != nil || string(b) != want {
		t.Fatalf("got %s, %v", b, err)
	}
}
