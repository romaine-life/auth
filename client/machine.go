// Package client keeps human sign-in and machine authentication distinct.
package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const BaseURL = "https://auth.romaine.life"
const TokenURL = BaseURL + "/api/auth/device/token"
const MachineTokenFile = "machine-token.json"
const HumanTokenFile = "user-token.json"

type AuthError struct{ Kind, Reason, Detail string }

func (e *AuthError) Error() string { return "machine sign-in: " + e.Detail }

var machineRegistration = ReadRegistration
var machineKey = openPlatformKey
var requestClient = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

type Registration struct {
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
	TokenURL string `json:"token_url"`
	Subject  string `json:"machine_subject,omitempty"`
}
type Credentials struct {
	Token       string `json:"token"`
	ExpiresAt   int64  `json:"expires_at"`
	Subject     string `json:"subject,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	Principal   string `json:"principal,omitempty"`
}
type Claims struct {
	Sub     string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Role    string `json:"role"`
	Purpose string `json:"purpose"`
	Device  string `json:"device"`
	Exp     int64  `json:"exp"`
	Apps    struct {
		Fzt struct {
			OwnerSub string `json:"owner_sub"`
		} `json:"fzt"`
	} `json:"apps"`
}

func ParseClaims(token string) (Claims, error) {
	var claims Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, errors.New("not a JWT")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, err
	}
	err = json.Unmarshal(data, &claims)
	return claims, err
}
func IsMachine(c Claims) bool {
	return c.Role == "service" && c.Purpose == "machine" && strings.HasPrefix(c.Sub, "device:") && c.Device != ""
}
func IsHuman(c Claims) bool {
	return (c.Role == "admin" || c.Role == "user") && c.Device == "" && c.Purpose == "" && c.Sub != ""
}
func TreeOwner(c Claims) (string, error) {
	if IsHuman(c) {
		return c.Sub, nil
	}
	if IsMachine(c) && c.Apps.Fzt.OwnerSub != "" {
		return c.Apps.Fzt.OwnerSub, nil
	}
	return "", errors.New("this account has no menu/bookmark owner grant")
}
func ConfigDir() string {
	if d := os.Getenv("FZT_CONFIG_DIR"); d != "" {
		return d
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".fzt-automate")
}
func registrationPath() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".romaine-device.json")
}
func ReadRegistration() (Registration, error) {
	var r Registration
	err := readJSON(registrationPath(), &r)
	if err != nil {
		return r, &AuthError{Kind: "unregistered", Detail: "this machine is not enrolled"}
	}
	if r.DeviceID == "" || r.TokenURL != TokenURL {
		return r, errors.New("unrecognized machine registration")
	}
	return r, nil
}
func readJSON(path string, out any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(bytes.TrimPrefix(b, []byte{239, 187, 191}), out)
}
func Save(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".credential-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = protectFile(f.Name()); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func ReadMachineToken(dir string) (string, error) {
	var cache Credentials
	if readJSON(filepath.Join(dir, MachineTokenFile), &cache) == nil {
		c, e := ParseClaims(cache.Token)
		if e == nil && IsMachine(c) && c.Exp > time.Now().Add(5*time.Minute).Unix() {
			return cache.Token, nil
		}
	}
	result, e := Exchange(context.Background(), nil)
	if e != nil {
		return "", e
	}
	c, e := ParseClaims(result.Token)
	if e != nil || !IsMachine(c) {
		return "", errors.New("auth returned a non-machine token")
	}
	if err := Save(filepath.Join(dir, MachineTokenFile), result); err != nil {
		return "", err
	}
	return result.Token, nil
}
func ReadHumanToken(dir string) (string, error) {
	var cache Credentials
	if e := readJSON(filepath.Join(dir, HumanTokenFile), &cache); e != nil {
		return "", errors.New("personal sign-in required: run romaine-auth user-login")
	}
	c, e := ParseClaims(cache.Token)
	if e != nil || !IsHuman(c) || c.Exp <= time.Now().Add(time.Minute).Unix() {
		return "", errors.New("personal sign-in expired: run romaine-auth user-login")
	}
	return cache.Token, nil
}

type signer interface {
	SignDigest([]byte) ([]byte, error)
	Close()
}
type softwareSigner struct{ k *ecdsa.PrivateKey }

func (s softwareSigner) Close() {}
func (s softwareSigner) SignDigest(d []byte) ([]byte, error) {
	r, t, e := ecdsa.Sign(rand.Reader, s.k, d)
	if e != nil {
		return nil, e
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	t.FillBytes(out[32:])
	return out, nil
}
func signAssertion(reg Registration, s signer, fields map[string]string) (string, error) {
	nonce := make([]byte, 16)
	if _, e := rand.Read(nonce); e != nil {
		return "", e
	}
	now := time.Now().Unix()
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": reg.DeviceID, "typ": "JWT"})
	canonical, _ := json.Marshal(fields)
	digest := sha256.Sum256(canonical)
	p, _ := json.Marshal(map[string]any{"iss": reg.DeviceID, "sub": reg.DeviceID, "aud": TokenURL, "iat": now, "exp": now + 120, "jti": hex.EncodeToString(nonce), "request_hash": hex.EncodeToString(digest[:])})
	b64 := base64.RawURLEncoding.EncodeToString
	input := b64(h) + "." + b64(p)
	hash := sha256.Sum256([]byte(input))
	sig, e := s.SignDigest(hash[:])
	if e != nil {
		return "", e
	}
	if len(sig) != 64 {
		return "", errors.New("invalid ES256 signature")
	}
	return input + "." + b64(sig), nil
}
func Exchange(ctx context.Context, fields map[string]string) (Credentials, error) {
	var result Credentials
	reg, e := machineRegistration()
	if e != nil {
		return result, e
	}
	s, e := machineKey(false)
	if e != nil {
		return result, &AuthError{Kind: "key", Detail: "the machine key is unavailable or locked"}
	}
	defer s.Close()
	if fields == nil {
		fields = map[string]string{}
	}
	if _, ok := fields["audience"]; !ok {
		fields = cloneFields(fields)
		fields["audience"] = "machine"
	}
	assertion, e := signAssertion(reg, s, fields)
	if e != nil {
		return result, e
	}
	body := map[string]string{"assertion": assertion}
	for k, v := range fields {
		if k == "assertion" {
			return result, errors.New("invalid exchange field")
		}
		body[k] = v
	}
	e = post(ctx, TokenURL, body, "", &result)
	return result, e
}
func cloneFields(fields map[string]string) map[string]string {
	copy := make(map[string]string, len(fields)+1)
	for key, value := range fields {
		copy[key] = value
	}
	return copy
}
func post(ctx context.Context, url string, body any, bearer string, out any) error {
	b, e := json.Marshal(body)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, e := requestClient.Do(req)
	if e != nil {
		return &AuthError{Kind: "unreachable", Detail: "cannot reach auth.romaine.life"}
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		var refusal struct {
			Reason string `json:"reason"`
			Error  string `json:"error"`
		}
		json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&refusal)
		kind := "refused"
		if response.StatusCode >= 500 {
			kind = "unreachable"
		}
		if refusal.Reason == "device_revoked" {
			kind = "revoked"
		}
		if refusal.Reason == "device_not_registered" {
			kind = "unregistered"
		}
		return &AuthError{Kind: kind, Reason: refusal.Reason, Detail: fmt.Sprintf("auth refused this machine (HTTP %d, %s)", response.StatusCode, refusal.Reason)}
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(out)
}
func Enroll(ctx context.Context, name string) (Registration, error) {
	var reg Registration
	s, e := openPlatformKey(true)
	if e != nil {
		return reg, e
	}
	s.Close()
	jwk, e := publicJWK()
	if e != nil {
		return reg, e
	}
	human, e := HumanLogin(ctx)
	if e != nil {
		return reg, e
	}
	e = post(ctx, BaseURL+"/api/auth/device/enroll", map[string]any{"name": name, "public_key_jwk": jwk}, human.Token, &reg)
	if e != nil {
		return reg, e
	}
	if reg.TokenURL != TokenURL || reg.DeviceID == "" {
		return reg, errors.New("invalid enrollment response")
	}
	return reg, Save(registrationPath(), reg)
}
