package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// openProjectFixture serves the device's OpenBao login and its stored OpenProject client,
// and stands in for OpenProject's token endpoint with answer.
func openProjectFixture(t *testing.T, stored string, answer func(form url.Values) (int, string)) *int {
	t.Helper()
	calls := 0
	baoFixture(t, func(r *http.Request) (int, string) {
		switch r.URL.Path {
		case "/v1/auth/device-testpc/login":
			return 200, `{"auth":{"client_token":"bao-token"}}`
		case "/v1/secret/data/devices/testpc/openproject":
			if r.Header.Get("X-Vault-Token") != "bao-token" {
				t.Fatal("the client read without the device's login")
			}
			return 200, stored
		}
		t.Fatalf("unexpected OpenBao call %s", r.URL.Path)
		return 0, ""
	})
	old := openProjectClient
	openProjectClient = &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != OpenProjectURL+"/oauth/token" || r.Method != http.MethodPost {
			t.Fatalf("unexpected OpenProject call %s %s", r.Method, r.URL)
		}
		calls++
		b, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(b))
		status, body := answer(form)
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	t.Cleanup(func() { openProjectClient = old })
	return &calls
}

const storedClient = `{"data":{"data":{"client_id":"pc-client","client_secret":"pc-secret"}}}`

func TestOpenProjectSignsInAtHomeWithTheDevicesOwnClient(t *testing.T) {
	calls := openProjectFixture(t, storedClient, func(form url.Values) (int, string) {
		if form.Get("grant_type") != "client_credentials" || form.Get("scope") != "api_v3" ||
			form.Get("client_id") != "pc-client" || form.Get("client_secret") != "pc-secret" {
			t.Fatalf("bad sign-in %v", form)
		}
		return 200, `{"access_token":"op-token","token_type":"Bearer","expires_in":7200}`
	})
	got, err := ReadOpenProjectCredentials(context.Background())
	if err != nil || got.Token != "op-token" || got.Subject != "testpc" {
		t.Fatalf("got %+v, %v", got, err)
	}
	// The saved token is reused with no further calls.
	again, err := ReadOpenProjectCredentials(context.Background())
	if err != nil || again.Token != "op-token" || *calls != 1 {
		t.Fatalf("reuse: %+v, %v, %d sign-ins", again, err, *calls)
	}
}

func TestOpenProjectRefusesAMissingClientAndABadAnswer(t *testing.T) {
	openProjectFixture(t, `{"data":{"data":{}}}`, func(url.Values) (int, string) {
		t.Fatal("signed in with no client")
		return 0, ""
	})
	if _, err := ReadOpenProjectCredentials(context.Background()); err == nil || !strings.Contains(err.Error(), "no OpenProject client") {
		t.Fatalf("missing client: %v", err)
	}
	for _, answer := range []struct {
		status int
		body   string
	}{
		{401, `{"error":"invalid_client"}`},
		{200, `{"access_token":"x","token_type":"mac","expires_in":60}`},
		{200, `{"access_token":"x","token_type":"Bearer","expires_in":999999}`},
		{200, `not json`},
	} {
		openProjectFixture(t, storedClient, func(url.Values) (int, string) { return answer.status, answer.body })
		if got, err := ReadOpenProjectCredentials(context.Background()); err == nil {
			b, _ := json.Marshal(got)
			t.Fatalf("accepted %d %s as %s", answer.status, answer.body, b)
		}
	}
}

func TestOpenProjectRefusalCarriesItsReason(t *testing.T) {
	for _, answer := range []struct {
		status int
		body   string
		want   string
	}{
		{400, `{"_type":"Error","errorIdentifier":"urn:openproject-org:api:v3:errors:InvalidRequestBody","message":"The request could not be parsed as JSON."}`,
			"OpenProject returned HTTP 400 urn:openproject-org:api:v3:errors:InvalidRequestBody: The request could not be parsed as JSON."},
		{422, `{"_type":"Error","errorIdentifier":"urn:openproject-org:api:v3:errors:MultipleErrors","message":"Multiple field constraints have been violated.","_embedded":{"errors":[{"message":"Subject can't be blank."},{"message":"Type is not set."}]}}`,
			"Multiple field constraints have been violated. (Subject can't be blank.; Type is not set.)"},
		{502, `Bad Gateway`, "OpenProject returned HTTP 502: Bad Gateway"},
		{500, ``, "OpenProject returned HTTP 500"},
	} {
		err := openProjectError(&http.Response{StatusCode: answer.status, Body: io.NopCloser(strings.NewReader(answer.body))})
		if err == nil || !strings.Contains(err.Error(), answer.want) {
			t.Fatalf("HTTP %d %s: got %v, want %q", answer.status, answer.body, err, answer.want)
		}
	}
}
