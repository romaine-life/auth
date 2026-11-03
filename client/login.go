package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"time"
)

func randomText() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func HumanLogin(ctx context.Context) (Credentials, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var result Credentials
	verifier, state := randomText(), randomText()
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	var listener net.Listener
	var err error
	for port := 8723; port < 8783; port++ {
		listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			break
		}
	}
	if listener == nil {
		return result, errors.New("cannot bind a personal sign-in callback")
	}
	redirect := "http://" + listener.Addr().String() + "/callback"
	codes := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Query().Get("state") != state || r.URL.Query().Get("code") == "" {
			http.Error(w, "Invalid sign-in callback", 400)
			return
		}
		select {
		case codes <- r.URL.Query().Get("code"):
			io.WriteString(w, "Signed in. You can return to the terminal.")
		default:
			http.Error(w, "Already used", 409)
		}
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go server.Serve(listener)
	defer server.Close()
	query := url.Values{"redirect_uri": {redirect}, "state": {state}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	target := BaseURL + "/api/auth/cli/user-login?" + query.Encode()
	if err = openBrowser(target); err != nil {
		return result, errors.New("cannot open the personal sign-in browser")
	}
	var code string
	select {
	case code = <-codes:
	case <-ctx.Done():
		return result, errors.New("personal sign-in timed out")
	}
	if err = post(ctx, BaseURL+"/api/auth/cli/user-token", map[string]string{"grant_type": "authorization_code", "code": code, "code_verifier": verifier, "redirect_uri": redirect}, "", &result); err != nil {
		return result, err
	}
	claims, err := ParseClaims(result.Token)
	if err != nil || !IsHuman(claims) {
		return result, errors.New("personal flow returned a non-human token")
	}
	result.ExpiresAt = claims.Exp
	return result, nil
}
func UserLogin(ctx context.Context, dir string) error {
	token, err := HumanLogin(ctx)
	if err != nil {
		return err
	}
	return Save(filepath.Join(dir, HumanTokenFile), token)
}
