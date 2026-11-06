package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// BaoURL is the home secret store (nelsong6/openbao). A device logs in there with its
// own key, at the mount that trusts that key alone, with no call to auth.romaine.life.
const BaoURL = "https://bao.home.romaine.life"

var homeRole = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func signBaoLogin(reg Registration, s signer) (string, error) {
	nonce := make([]byte, 16)
	if _, e := rand.Read(nonce); e != nil {
		return "", e
	}
	now := time.Now().Unix()
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT"})
	p, _ := json.Marshal(map[string]any{"iss": "home-device", "sub": reg.Name, "aud": BaoURL, "iat": now, "exp": now + 120, "jti": hex.EncodeToString(nonce)})
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

func baoCall(ctx context.Context, method, path, baoToken string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return e
		}
		reader = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, BaoURL+path, reader)
	if e != nil {
		return e
	}
	if baoToken != "" {
		req.Header.Set("X-Vault-Token", baoToken)
	}
	response, e := requestClient.Do(req)
	if e != nil {
		return &AuthError{Kind: "unreachable", Detail: "cannot reach OpenBao at " + BaoURL}
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		var refusal struct {
			Errors []string `json:"errors"`
		}
		json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&refusal)
		return &AuthError{Kind: "refused", Detail: fmt.Sprintf("OpenBao refused this machine (HTTP %d, %s)", response.StatusCode, strings.Join(refusal.Errors, "; "))}
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(out)
}

// HomeToken returns a short-lived token OpenBao signs for a home service, which the
// service checks against OpenBao's published keys.
func HomeToken(ctx context.Context, role string) (Credentials, error) {
	var result Credentials
	if !homeRole.MatchString(role) {
		return result, errors.New("invalid home token role")
	}
	reg, e := machineRegistration()
	if e != nil {
		return result, e
	}
	s, e := machineKey(false)
	if e != nil {
		return result, &AuthError{Kind: "key", Detail: "the machine key is unavailable or locked"}
	}
	defer s.Close()
	assertion, e := signBaoLogin(reg, s)
	if e != nil {
		return result, e
	}
	var login struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if e := baoCall(ctx, http.MethodPost, "/v1/auth/device-"+reg.Name+"/login", "", map[string]string{"role": "login", "jwt": assertion}, &login); e != nil {
		return result, e
	}
	if login.Auth.ClientToken == "" {
		return result, errors.New("OpenBao returned no login")
	}
	var issued struct {
		Data struct {
			Token string `json:"token"`
			TTL   int64  `json:"ttl"`
		} `json:"data"`
	}
	if e := baoCall(ctx, http.MethodGet, "/v1/identity/oidc/token/"+role, login.Auth.ClientToken, nil, &issued); e != nil {
		return result, e
	}
	if issued.Data.Token == "" {
		return result, errors.New("OpenBao returned no token")
	}
	return Credentials{Token: issued.Data.Token, ExpiresAt: time.Now().Unix() + issued.Data.TTL}, nil
}
