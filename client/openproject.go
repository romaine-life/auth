package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

func ReadOpenProjectCredentials(ctx context.Context) (Credentials, error) {
	registration, err := machineRegistration()
	if err != nil {
		return Credentials{}, err
	}
	subject := registration.Subject
	if subject == "" {
		token, e := ReadMachineToken(ConfigDir())
		if e != nil {
			return Credentials{}, e
		}
		claims, e := ParseClaims(token)
		if e != nil {
			return Credentials{}, e
		}
		subject = claims.Sub
	}
	var credentials Credentials
	file := filepath.Join(ConfigDir(), "openproject-token.json")
	if readJSON(file, &credentials) == nil && credentials.Subject == subject && credentials.Token != "" && credentials.ExpiresAt > time.Now().Add(5*time.Minute).Unix() {
		return credentials, nil
	}
	credentials, err = Exchange(ctx, map[string]string{"audience": "openproject"})
	if err != nil {
		return Credentials{}, err
	}
	if credentials.Subject != subject || credentials.Token == "" || credentials.ExpiresAt <= time.Now().Unix() {
		return Credentials{}, errors.New("invalid machine OpenProject credential response")
	}
	if err = Save(file, credentials); err != nil {
		return Credentials{}, err
	}
	return credentials, nil
}

func OpenProjectRequest(ctx context.Context, method, path string, body []byte, out io.Writer) error {
	parsed, err := url.Parse(path)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/api/v3/") {
		return errors.New("an OpenProject API path is required")
	}
	credentials, err := ReadOpenProjectCredentials(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://openproject.romaine.life"+parsed.RequestURI(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+credentials.Token)
	req.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return errors.New("cannot reach OpenProject")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("OpenProject returned HTTP %d", response.StatusCode)
	}
	_, err = io.Copy(out, response.Body)
	return err
}
