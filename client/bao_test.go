package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func baoFixture(t *testing.T, handle func(*http.Request) (int, string)) *ecdsa.PrivateKey {
	t.Helper()
	t.Setenv("FZT_CONFIG_DIR", t.TempDir())
	oldReg, oldKey, oldClient := machineRegistration, machineKey, baoClient
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	machineRegistration = func() (Registration, error) {
		return Registration{DeviceID: "dev_test", Name: "testpc", TokenURL: TokenURL}, nil
	}
	machineKey = func(bool) (signer, error) { return softwareSigner{key}, nil }
	baoClient = &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "bao.home.romaine.life" {
			t.Fatalf("unexpected destination %s", r.URL)
		}
		status, answer := handle(r)
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(answer)), Request: r}, nil
	})}
	t.Cleanup(func() { machineRegistration, machineKey, baoClient = oldReg, oldKey, oldClient })
	return key
}

func TestHomeTokenLogsInWithTheDeviceKeyAlone(t *testing.T) {
	var key *ecdsa.PrivateKey
	key = baoFixture(t, func(r *http.Request) (int, string) {
		switch r.URL.Path {
		case "/v1/auth/device-testpc/login":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			parts := strings.Split(body["jwt"], ".")
			if body["role"] != "login" || len(parts) != 3 {
				t.Fatal("bad login request")
			}
			raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			var claims map[string]any
			json.Unmarshal(raw, &claims)
			if claims["iss"] != "home-device" || claims["sub"] != "testpc" || claims["aud"] != BaoURL {
				t.Fatalf("bad claims %v", claims)
			}
			digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if len(sig) != 64 || !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
				t.Fatal("signature does not verify")
			}
			return 200, `{"auth":{"client_token":"bao-login"}}`
		case "/v1/identity/oidc/token/shows":
			if r.Header.Get("X-Vault-Token") != "bao-login" {
				t.Fatal("not the login's token")
			}
			return 200, `{"data":{"client_id":"shows","token":"signed-token","ttl":300}}`
		}
		t.Fatalf("unexpected path %s", r.URL.Path)
		return 0, ""
	})
	result, e := HomeToken(context.Background(), "shows")
	if e != nil {
		t.Fatal(e)
	}
	if result.Token != "signed-token" || result.ExpiresAt == 0 {
		t.Fatalf("bad result %+v", result)
	}
}

func TestHomeTokenRefusals(t *testing.T) {
	baoFixture(t, func(r *http.Request) (int, string) { return 403, `{"errors":["permission denied"]}` })
	_, e := HomeToken(context.Background(), "shows")
	if e == nil || !strings.Contains(e.Error(), "HTTP 403, permission denied") {
		t.Fatal(e)
	}
	for _, role := range []string{"", "../sys", "Shows", "a/b"} {
		if _, e := HomeToken(context.Background(), role); e == nil || !strings.Contains(e.Error(), "invalid home token role") {
			t.Fatalf("%q: %v", role, e)
		}
	}
}

// issuingFixture answers logins and counts them; each token is named after its login.
func issuingFixture(t *testing.T, ttl int) *int {
	t.Helper()
	logins := 0
	baoFixture(t, func(r *http.Request) (int, string) {
		if strings.HasSuffix(r.URL.Path, "/login") {
			logins++
			return 200, `{"auth":{"client_token":"bao-login"}}`
		}
		return 200, fmt.Sprintf(`{"data":{"token":"token-%d-%s","ttl":%d}}`, logins, strings.TrimPrefix(r.URL.Path, "/v1/identity/oidc/token/"), ttl)
	})
	return &logins
}

func TestHomeTokenIsReusedWithNoCallAndNoKey(t *testing.T) {
	logins := issuingFixture(t, 300)
	first, e := HomeToken(context.Background(), "shows")
	if e != nil {
		t.Fatal(e)
	}
	machineKey = func(bool) (signer, error) { t.Fatal("the key was used for a cached token"); return nil, nil }
	baoClient = &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		t.Fatalf("a cached token called %s", r.URL)
		return nil, nil
	})}
	second, e := HomeToken(context.Background(), "shows")
	if e != nil {
		t.Fatal(e)
	}
	if second.Token != first.Token || *logins != 1 {
		t.Fatalf("second %+v, %d logins", second, *logins)
	}
}

func TestHomeTokenNearExpiryRenews(t *testing.T) {
	logins := issuingFixture(t, 300)
	HomeToken(context.Background(), "shows")
	if e := Save(homeTokenPath("shows"), Credentials{Token: "old", ExpiresAt: time.Now().Add(homeTokenMargin - time.Second).Unix(), Subject: "testpc"}); e != nil {
		t.Fatal(e)
	}
	result, e := HomeToken(context.Background(), "shows")
	if e != nil || result.Token == "old" || *logins != 2 {
		t.Fatalf("%+v, %v, %d logins", result, e, *logins)
	}
}

func TestHomeTokenCacheIsPerRole(t *testing.T) {
	logins := issuingFixture(t, 300)
	shows, _ := HomeToken(context.Background(), "shows")
	other, e := HomeToken(context.Background(), "session-index")
	if e != nil || other.Token == shows.Token || !strings.HasSuffix(other.Token, "session-index") || *logins != 2 {
		t.Fatalf("%+v, %v, %d logins", other, e, *logins)
	}
}

func TestHomeTokenIgnoresABadCache(t *testing.T) {
	theirs := func(subject string) func(string) error {
		return func(path string) error {
			return Save(path, Credentials{Token: "theirs", ExpiresAt: time.Now().Add(time.Hour).Unix(), Subject: subject})
		}
	}
	for name, write := range map[string]func(string) error{
		"corrupt":        func(path string) error { return os.WriteFile(path, []byte("{not json"), 0600) },
		"another device": theirs("otherpc"),
		"no device":      theirs(""),
	} {
		t.Run(name, func(t *testing.T) {
			logins := issuingFixture(t, 300)
			if e := os.MkdirAll(ConfigDir(), 0700); e != nil {
				t.Fatal(e)
			}
			if e := write(homeTokenPath("shows")); e != nil {
				t.Fatal(e)
			}
			result, e := HomeToken(context.Background(), "shows")
			if e != nil || result.Token == "theirs" || *logins != 1 {
				t.Fatalf("%+v, %v, %d logins", result, e, *logins)
			}
		})
	}
}

func TestHomeTokenSurvivesACacheItCannotWrite(t *testing.T) {
	issuingFixture(t, 300)
	blocked := filepath.Join(t.TempDir(), "file")
	if e := os.WriteFile(blocked, nil, 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("FZT_CONFIG_DIR", filepath.Join(blocked, "dir"))
	if result, e := HomeToken(context.Background(), "shows"); e != nil || result.Token == "" {
		t.Fatalf("%+v, %v", result, e)
	}
}

func TestOpenBaoTimeoutIsNotUnreachable(t *testing.T) {
	for name, failure := range map[string]struct {
		err  error
		kind string
		text string
	}{
		"timeout":     {context.DeadlineExceeded, "timeout", "took too long"},
		"unreachable": {errors.New("connection refused"), "unreachable", "cannot reach OpenBao"},
	} {
		t.Run(name, func(t *testing.T) {
			baoFixture(t, nil)
			baoClient = &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) { return nil, failure.err })}
			_, e := HomeToken(context.Background(), "shows")
			var ae *AuthError
			if !errors.As(e, &ae) || ae.Kind != failure.kind || !strings.Contains(e.Error(), failure.text) {
				t.Fatal(e)
			}
		})
	}
}

func TestOpenBaoHasItsOwnBudget(t *testing.T) {
	if baoClient.Timeout != time.Minute || requestClient.Timeout != 20*time.Second {
		t.Fatalf("OpenBao %v, shared %v", baoClient.Timeout, requestClient.Timeout)
	}
	if baoClient.CheckRedirect == nil {
		t.Fatal("OpenBao calls would follow a redirect")
	}
}

func homeClaims(t *testing.T, iss, device, owner string) Claims {
	t.Helper()
	c, err := ParseClaims(jwt(map[string]any{"iss": iss, "sub": "2f1c3a40-entity", "device": device, "apps": map[string]any{"fzt": map[string]string{"owner_sub": owner}}}))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestHomeTokenSelectsItsTreeOwner(t *testing.T) {
	owner, err := TreeOwner(homeClaims(t, HomeIssuer, "testpc", "owner"))
	if err != nil || owner != "owner" {
		t.Fatalf("owner %q, error %v", owner, err)
	}
}

func TestHomeTokenWithoutAnOwnerIsRefused(t *testing.T) {
	if owner, err := TreeOwner(homeClaims(t, HomeIssuer, "testpc", "")); err == nil {
		t.Fatalf("got owner %q", owner)
	}
}

func TestHomeDeviceNeedsTheIssuerAndADevice(t *testing.T) {
	if !IsHomeDevice(homeClaims(t, HomeIssuer, "testpc", "owner")) {
		t.Fatal("a home token wasn't recognized")
	}
	for _, c := range []Claims{
		homeClaims(t, HomeIssuer, "", "owner"),
		homeClaims(t, HomeIssuer+".example.com", "testpc", "owner"),
		homeClaims(t, "https://auth.romaine.life", "testpc", "owner"),
	} {
		if IsHomeDevice(c) {
			t.Fatalf("%+v counted as a home device", c)
		}
		if owner, err := TreeOwner(c); err == nil {
			t.Fatalf("%+v selected owner %q", c, owner)
		}
	}
}
