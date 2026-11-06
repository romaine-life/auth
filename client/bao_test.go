package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
)

func baoFixture(t *testing.T, handle func(*http.Request) (int, string)) *ecdsa.PrivateKey {
	t.Helper()
	oldReg, oldKey, oldClient := machineRegistration, machineKey, requestClient
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	machineRegistration = func() (Registration, error) {
		return Registration{DeviceID: "dev_test", Name: "testpc", TokenURL: TokenURL}, nil
	}
	machineKey = func(bool) (signer, error) { return softwareSigner{key}, nil }
	requestClient = &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "bao.home.romaine.life" {
			t.Fatalf("unexpected destination %s", r.URL)
		}
		status, answer := handle(r)
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(answer)), Request: r}, nil
	})}
	t.Cleanup(func() { machineRegistration, machineKey, requestClient = oldReg, oldKey, oldClient })
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
