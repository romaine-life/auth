package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// OpenProjectURL is the home OpenProject (nelsong6/openproject). The home network's DNS
// answers its name, so machine calls stay at home (OPADMIN-23).
const OpenProjectURL = "https://openproject.romaine.life"

var openProjectClient = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// ReadOpenProjectCredentials returns a token for the home OpenProject as this machine.
// The machine reads its own OpenProject OAuth client from OpenBao with its device login
// (secret/devices/<device>/openproject) and signs in to OpenProject itself, with no
// cloud in the path. A token with time left is reused from the config dir.
func ReadOpenProjectCredentials(ctx context.Context) (Credentials, error) {
	reg, err := machineRegistration()
	if err != nil {
		return Credentials{}, err
	}
	var credentials Credentials
	file := filepath.Join(ConfigDir(), "openproject-token.json")
	if readJSON(file, &credentials) == nil && credentials.Subject == reg.Name && credentials.Token != "" && credentials.ExpiresAt > time.Now().Add(5*time.Minute).Unix() {
		return credentials, nil
	}
	baoToken, err := baoLogin(ctx, reg)
	if err != nil {
		return Credentials{}, err
	}
	var stored struct {
		Data struct {
			Data struct {
				ClientID     string `json:"client_id"`
				ClientSecret string `json:"client_secret"`
			} `json:"data"`
		} `json:"data"`
	}
	if err = baoCall(ctx, http.MethodGet, "/v1/secret/data/devices/"+reg.Name+"/openproject", baoToken, nil, &stored); err != nil {
		return Credentials{}, err
	}
	client := stored.Data.Data
	if client.ClientID == "" || client.ClientSecret == "" {
		return Credentials{}, &AuthError{Kind: "refused", Detail: "this machine has no OpenProject client in OpenBao"}
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"api_v3"}, "client_id": {client.ClientID}, "client_secret": {client.ClientSecret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, OpenProjectURL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return Credentials{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := openProjectClient.Do(req)
	if err != nil {
		return Credentials{}, &AuthError{Kind: "unreachable", Detail: "cannot reach OpenProject"}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Credentials{}, &AuthError{Kind: "refused", Detail: fmt.Sprintf("OpenProject refused this machine's sign-in (HTTP %d)", response.StatusCode)}
	}
	var issued struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&issued); err != nil || issued.AccessToken == "" ||
		!strings.EqualFold(issued.TokenType, "bearer") || issued.ExpiresIn <= 0 || issued.ExpiresIn > 7200 {
		return Credentials{}, errors.New("OpenProject returned an invalid token response")
	}
	credentials = Credentials{Token: issued.AccessToken, ExpiresAt: time.Now().Unix() + issued.ExpiresIn, Subject: reg.Name}
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
	req, err := http.NewRequestWithContext(ctx, method, OpenProjectURL+parsed.RequestURI(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+credentials.Token)
	req.Header.Set("Content-Type", "application/json")
	response, err := openProjectClient.Do(req)
	if err != nil {
		return errors.New("cannot reach OpenProject")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return openProjectError(response)
	}
	_, err = io.Copy(out, response.Body)
	return err
}

// openProjectError reports a refused API call with OpenProject's own reason: its error
// body's errorIdentifier and message, and each of a MultipleErrors body's inner errors.
func openProjectError(response *http.Response) error {
	type apiError struct {
		ErrorIdentifier string `json:"errorIdentifier"`
		Message         string `json:"message"`
		Embedded        struct {
			Errors []struct {
				ErrorIdentifier string `json:"errorIdentifier"`
				Message         string `json:"message"`
			} `json:"errors"`
		} `json:"_embedded"`
	}
	var body apiError
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if json.Unmarshal(raw, &body) != nil || (body.Message == "" && body.ErrorIdentifier == "") {
		detail := strings.TrimSpace(string(raw))
		if len(detail) > 500 {
			detail = detail[:500] + "..."
		}
		if detail == "" {
			return fmt.Errorf("OpenProject returned HTTP %d", response.StatusCode)
		}
		return fmt.Errorf("OpenProject returned HTTP %d: %s", response.StatusCode, detail)
	}
	reasons := []string{}
	for _, inner := range body.Embedded.Errors {
		reasons = append(reasons, inner.Message)
	}
	message := body.Message
	if len(reasons) > 0 && message != strings.Join(reasons, " ") {
		message += " (" + strings.Join(reasons, "; ") + ")"
	}
	return fmt.Errorf("OpenProject returned HTTP %d %s: %s", response.StatusCode, body.ErrorIdentifier, message)
}
