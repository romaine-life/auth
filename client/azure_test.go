package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// azureFixture answers auth's Azure access routes from a list, one answer per call, and
// records each request.
func azureFixture(t *testing.T, answers ...string) *[]*http.Request {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("FZT_CONFIG_DIR", dir)
	Save(filepath.Join(dir, MachineTokenFile), Credentials{Token: machineJWT(time.Now().Add(time.Hour).Unix())})
	seen := []*http.Request{}
	old := requestClient
	requestClient = &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		if len(seen) >= len(answers) {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL)
		}
		answer := answers[len(seen)]
		seen = append(seen, r)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(answer)), Request: r}, nil
	})}
	t.Cleanup(func() { requestClient = old })
	return &seen
}

func TestAzureRequestSendsReasonWithMachineToken(t *testing.T) {
	seen := azureFixture(t, `{"id":"aza_1","status":"pending","minutes":30,"approve_url":"https://auth.romaine.life/azure-access/aza_1"}`)
	req, err := RequestAzureAccess(context.Background(), "read the cluster", 30)
	if err != nil || req.ID != "aza_1" || req.ApproveURL == "" {
		t.Fatalf("got %+v, %v", req, err)
	}
	r := (*seen)[0]
	if r.Method != "POST" || r.URL.String() != BaseURL+"/api/azure-access/requests" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		t.Fatalf("sent %s %s", r.Method, r.URL)
	}
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	if body["reason"] != "read the cluster" || body["minutes"] != float64(30) {
		t.Fatalf("body %v", body)
	}
}

func TestAzureWaitAsksAgainUntilDecided(t *testing.T) {
	seen := azureFixture(t,
		`{"id":"aza_1","status":"pending"}`,
		`{"id":"aza_1","status":"pending"}`,
		`{"id":"aza_1","status":"approved","decided_by":"nelson@romaine.life","grant_expires_at":1900000000}`)
	got, err := WaitAzureAccess(context.Background(), "aza_1")
	if err != nil || got.Status != "approved" || len(*seen) != 3 {
		t.Fatalf("got %+v after %d calls, %v", got, len(*seen), err)
	}
	if q := (*seen)[0].URL.Query().Get("wait"); q != "10" {
		t.Fatalf("each call should ask auth to hold it for a decision, wait=%q", q)
	}
}

func TestAzureLoginUsesTheFederatedToken(t *testing.T) {
	var got []string
	old := azCommand
	azCommand = func(_ context.Context, args ...string) error { got = args; return nil }
	t.Cleanup(func() { azCommand = old })
	err := AzureLogin(context.Background(), AzureToken{Token: "tok", ClientID: "cid", TenantID: "tid"})
	want := []string{"login", "--service-principal", "--username", "cid", "--tenant", "tid", "--federated-token", "tok", "--allow-no-subscriptions", "--output", "none"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("az %v, %v", got, err)
	}
}

func TestAzureTokenAsksForTheAzureAudience(t *testing.T) {
	answer, _ := json.Marshal(AzureToken{Token: "tok", ClientID: "cid", TenantID: "tid"})
	hits := fixture(t, 200, string(answer))
	got, err := GetAzureToken(context.Background())
	if err != nil || got.ClientID != "cid" || *hits != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestAzureRefusalCarriesAuthsMessage(t *testing.T) {
	old := requestClient
	requestClient = &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Header: make(http.Header), Request: r,
			Body: io.NopCloser(strings.NewReader(`{"error":"this machine has no approved Azure access","reason":"no_grant"}`))}, nil
	})}
	t.Cleanup(func() { requestClient = old })
	err := azureCall(context.Background(), "GET", BaseURL+"/x", "t", nil, &AzureRequest{})
	if err == nil || !strings.Contains(err.Error(), "no approved Azure access") {
		t.Fatalf("err %v", err)
	}
}
