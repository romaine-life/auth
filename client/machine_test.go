package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func jwt(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}
func machineJWT(exp int64) string {
	return jwt(map[string]any{"sub": "device:owner/testpc", "email": "machine@service.machine.romaine.life", "name": "Machine: testpc", "role": "service", "purpose": "machine", "device": "testpc", "exp": exp, "apps": map[string]any{"fzt": map[string]string{"owner_sub": "owner"}}})
}
func fixture(t *testing.T, status int, answer string) *int {
	t.Helper()
	hits := 0
	oldReg, oldKey, oldClient := machineRegistration, machineKey, requestClient
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	machineRegistration = func() (Registration, error) {
		return Registration{DeviceID: "dev_test", Name: "testpc", TokenURL: TokenURL}, nil
	}
	machineKey = func(bool) (signer, error) { return softwareSigner{key}, nil }
	requestClient = &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		hits++
		if r.URL.String() != TokenURL {
			t.Fatalf("unexpected credential destination %s", r.URL)
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(answer)), Request: r}, nil
	})}
	t.Cleanup(func() { machineRegistration, machineKey, requestClient = oldReg, oldKey, oldClient })
	return &hits
}
func TestMachineCacheNeverReusesHumanOrLegacyDeviceTokens(t *testing.T) {
	for _, wrong := range []string{jwt(map[string]any{"sub": "owner", "role": "admin", "exp": time.Now().Add(time.Hour).Unix()}), jwt(map[string]any{"sub": "owner", "role": "admin", "device": "testpc", "exp": time.Now().Add(time.Hour).Unix()})} {
		t.Run(wrong[:3]+strings.Split(wrong, ".")[1][:6], func(t *testing.T) {
			dir := t.TempDir()
			fresh := machineJWT(time.Now().Add(time.Hour).Unix())
			answer, _ := json.Marshal(Credentials{Token: fresh})
			hits := fixture(t, 200, string(answer))
			for _, name := range []string{MachineTokenFile, HumanTokenFile, "auth-token.json"} {
				if e := Save(filepath.Join(dir, name), Credentials{Token: wrong}); e != nil {
					t.Fatal(e)
				}
			}
			before, _ := os.ReadFile(filepath.Join(dir, HumanTokenFile))
			got, e := ReadMachineToken(dir)
			if e != nil || got != fresh || *hits != 1 {
				t.Fatalf("renewed=%v hits=%d err=%v", got == fresh, *hits, e)
			}
			after, _ := os.ReadFile(filepath.Join(dir, HumanTokenFile))
			if string(before) != string(after) {
				t.Fatal("machine renewal changed the human credential")
			}
		})
	}
}
func TestValidMachineCacheDoesNotContactKeyOrNetwork(t *testing.T) {
	dir := t.TempDir()
	token := machineJWT(time.Now().Add(time.Hour).Unix())
	Save(filepath.Join(dir, MachineTokenFile), Credentials{Token: token})
	hits := fixture(t, 500, "")
	machineKey = func(bool) (signer, error) { t.Fatal("cached token opened the key"); return nil, nil }
	got, e := ReadMachineToken(dir)
	if e != nil || got != token || *hits != 0 {
		t.Fatal("valid machine cache was not used")
	}
}
func TestExpiringMachineCacheRenews(t *testing.T) {
	dir := t.TempDir()
	Save(filepath.Join(dir, MachineTokenFile), Credentials{Token: machineJWT(time.Now().Add(time.Minute).Unix())})
	fresh := machineJWT(time.Now().Add(time.Hour).Unix())
	answer, _ := json.Marshal(Credentials{Token: fresh})
	hits := fixture(t, 200, string(answer))
	got, e := ReadMachineToken(dir)
	if e != nil || got != fresh || *hits != 1 {
		t.Fatalf("renewal failed: %v", e)
	}
}
func TestExpiredHumanTokenNeverUsesMachineCredential(t *testing.T) {
	dir := t.TempDir()
	Save(filepath.Join(dir, HumanTokenFile), Credentials{Token: jwt(map[string]any{"sub": "owner", "role": "admin", "exp": time.Now().Add(-time.Minute).Unix()})})
	hits := fixture(t, 200, "{}")
	machineKey = func(bool) (signer, error) { t.Fatal("human token renewed from machine"); return nil, nil }
	if _, e := ReadHumanToken(dir); e == nil || *hits != 0 {
		t.Fatal("expired human token accepted or renewed")
	}
}
func TestRefusalsPreserveFailureState(t *testing.T) {
	for reason, kind := range map[string]string{"device_not_registered": "unregistered", "device_revoked": "revoked", "assertion_replayed": "refused", "account_not_approved": "refused"} {
		t.Run(reason, func(t *testing.T) {
			fixture(t, 401, `{"reason":"`+reason+`"}`)
			_, e := Exchange(context.Background(), nil)
			var ae *AuthError
			if !errors.As(e, &ae) || ae.Kind != kind || ae.Reason != reason {
				t.Fatalf("wrong refusal: %v", e)
			}
		})
	}
}
func TestAssertionsSignTheExactRequest(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fields := map[string]string{"audience": "ssh", "public_key": "key", "target": "nelsonpc", "user": "nelson"}
	token, e := signAssertion(Registration{DeviceID: "dev_abc"}, softwareSigner{key}, fields)
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(token, ".")
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	var claims map[string]any
	json.Unmarshal(body, &claims)
	canonical, _ := json.Marshal(fields)
	hash := sha256.Sum256(canonical)
	if claims["request_hash"] != hex.EncodeToString(hash[:]) || claims["aud"] != TokenURL || claims["sub"] != "dev_abc" || claims["iss"] != "dev_abc" {
		t.Fatal("assertion request binding is incorrect")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("signature does not verify")
	}
	again, _ := signAssertion(Registration{DeviceID: "dev_abc"}, softwareSigner{key}, fields)
	if parts[1] == strings.Split(again, ".")[1] {
		t.Fatal("assertions reused a nonce")
	}
}
func TestSSHConfigIsGlobalIdempotentAndPreservesExistingSettings(t *testing.T) {
	original := "PasswordAuthentication no\nMatch Group administrators\n  AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\n"
	config, e := SSHConfig(original, "C:/ProgramData/ssh")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasSuffix(config, original) || strings.Index(config, "TrustedUserCAKeys") > strings.Index(config, "Match Group") {
		t.Fatal("CA settings are inside a Match block or settings were lost")
	}
	again, e := SSHConfig(config, "C:/ProgramData/ssh")
	if e != nil || again != config {
		t.Fatal("host setup is not idempotent")
	}
	if _, e = SSHConfig("TrustedUserCAKeys /existing\n", "/etc/ssh"); e == nil {
		t.Fatal("overwrote another CA configuration")
	}
}
func TestLivePlatformKey(t *testing.T) {
	if os.Getenv("ROMAINE_MACHINE_KEY_LIVE") != "1" {
		t.Skip("explicit live keystore check")
	}
	s, e := openPlatformKey(false)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	jwk, e := publicJWK()
	if e != nil {
		t.Fatal(e)
	}
	x, e := base64.RawURLEncoding.DecodeString(jwk["x"])
	if e != nil {
		t.Fatal(e)
	}
	y, _ := base64.RawURLEncoding.DecodeString(jwk["y"])
	pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	hash := sha256.Sum256([]byte("romaine-machine-key-check"))
	sig, e := s.SignDigest(hash[:])
	if e != nil || len(sig) != 64 {
		t.Fatalf("live signing: %v", e)
	}
	if !ecdsa.Verify(&pub, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("live platform key signature does not verify")
	}
}
