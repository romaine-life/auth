package client

// Tailnet join with no browser and no stored key (AUT-10): the machine proves itself to
// auth.romaine.life with its own key, auth answers with a federation token Tailscale's
// trust credential accepts, Tailscale trades it for a short-lived API token, and that
// mints a one-use, pre-approved auth key for the machine's own tags. A tagged node joined
// by key has no key expiry, so the join lasts until the node is removed.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/romaine-life/auth/internal/netclient"
)

// TailscaleToken is auth's federation token for the tailnet's trust credential.
type TailscaleToken struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	Subject   string `json:"subject"`
	Audience  string `json:"audience"` // api.tailscale.com/<trust credential client id>
}

// GetTailscaleToken asks auth for the machine's Tailscale federation token.
func GetTailscaleToken(ctx context.Context) (TailscaleToken, error) {
	var out TailscaleToken
	err := exchangeInto(ctx, map[string]string{"audience": "tailscale"}, &out)
	if err == nil && (out.Token == "" || !strings.HasPrefix(out.Audience, "api.tailscale.com/")) {
		err = errors.New("auth returned an incomplete Tailscale token")
	}
	return out, err
}

// TailscaleAPI is Tailscale's API; tests replace it.
var TailscaleAPI = "https://api.tailscale.com/api/v2"

// tailscaleHTTP follows redirects, as the default client it replaced did.
var tailscaleHTTP = netclient.New(netclient.Options{})

// TailnetAuthKey trades the federation token at Tailscale for a one-use, pre-approved,
// non-ephemeral auth key carrying tags, valid five minutes.
func TailnetAuthKey(ctx context.Context, t TailscaleToken, tags []string) (string, error) {
	if len(tags) == 0 {
		return "", errors.New("the machine advertises no tags; a key-joined node must carry one")
	}
	clientID := strings.TrimPrefix(t.Audience, "api.tailscale.com/")
	form := url.Values{"client_id": {clientID}, "jwt": {t.Token}}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := tailscaleCall(ctx, "POST", "/oauth/token-exchange", "", "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()), &tok); err != nil {
		return "", fmt.Errorf("Tailscale refused auth's token for %s: %w", t.Subject, err)
	}
	body, _ := json.Marshal(map[string]any{
		"capabilities": map[string]any{"devices": map[string]any{"create": map[string]any{
			"reusable": false, "ephemeral": false, "preauthorized": true, "tags": tags,
		}}},
		"expirySeconds": 300,
		"description":   "rejoin " + strings.TrimPrefix(t.Subject, "machine:"),
	})
	var key struct {
		Key string `json:"key"`
	}
	if err := tailscaleCall(ctx, "POST", "/tailnet/-/keys", tok.AccessToken, "application/json", bytes.NewReader(body), &key); err != nil {
		return "", fmt.Errorf("Tailscale wouldn't mint a key for %s with %s: %w", t.Subject, strings.Join(tags, ","), err)
	}
	if key.Key == "" {
		return "", errors.New("Tailscale returned no key")
	}
	return key.Key, nil
}

func tailscaleCall(ctx context.Context, method, path, bearer, contentType string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, TailscaleAPI+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := tailscaleHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
		return fmt.Errorf("%s %s: %s %s", method, path, resp.Status, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// TailscaleCommand runs the tailscale CLI and returns its output; tests replace it.
var TailscaleCommand = func(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "tailscale", args...).CombinedOutput()
}

// TailnetState is what the join needs from the local node.
type TailnetState struct {
	BackendState string
	Tags         []string // what the node advertises
	AcceptRoutes bool
	Unattended   bool
	Hostname     string
}

// ReadTailnetState reads the node's state and the prefs `tailscale up` must restate.
func ReadTailnetState(ctx context.Context) (TailnetState, error) {
	var s TailnetState
	out, err := TailscaleCommand(ctx, "status", "--json")
	if err != nil {
		return s, fmt.Errorf("tailscale status: %v: %s", err, strings.TrimSpace(string(out)))
	}
	var status struct{ BackendState string }
	if err := json.Unmarshal(out, &status); err != nil {
		return s, fmt.Errorf("tailscale status: %w", err)
	}
	out, err = TailscaleCommand(ctx, "debug", "prefs")
	if err != nil {
		return s, fmt.Errorf("tailscale debug prefs: %v: %s", err, strings.TrimSpace(string(out)))
	}
	var prefs struct {
		AdvertiseTags []string
		RouteAll      bool
		ForceDaemon   bool
		Hostname      string
	}
	if err := json.Unmarshal(out, &prefs); err != nil {
		return s, fmt.Errorf("tailscale debug prefs: %w", err)
	}
	return TailnetState{status.BackendState, prefs.AdvertiseTags, prefs.RouteAll, prefs.ForceDaemon, prefs.Hostname}, nil
}

// JoinTailnet signs the node in with a fresh key unless it is already running. It
// restates the node's own prefs, so the join changes nothing but the sign-in.
func JoinTailnet(ctx context.Context, force bool) (string, error) {
	s, err := ReadTailnetState(ctx)
	if err != nil {
		return "", err
	}
	if s.BackendState == "Running" && !force {
		return "already on the tailnet", nil
	}
	t, err := GetTailscaleToken(ctx)
	if err != nil {
		return "", err
	}
	key, err := TailnetAuthKey(ctx, t, s.Tags)
	if err != nil {
		return "", err
	}
	// The key goes by file, so it never shows in a process list.
	f, err := os.CreateTemp("", "tailnet-key-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	_, werr := f.WriteString(key)
	if cerr := f.Close(); werr != nil || cerr != nil {
		return "", errors.Join(werr, cerr)
	}
	args := []string{"up", "--auth-key=file:" + f.Name(),
		"--advertise-tags=" + strings.Join(s.Tags, ","),
		fmt.Sprintf("--accept-routes=%t", s.AcceptRoutes), "--timeout=60s"}
	if force {
		args = append(args, "--force-reauth")
	}
	if s.Unattended {
		args = append(args, "--unattended")
	}
	if s.Hostname != "" {
		args = append(args, "--hostname="+s.Hostname)
	}
	if out, err := TailscaleCommand(ctx, args...); err != nil {
		return "", fmt.Errorf("tailscale up: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return fmt.Sprintf("joined the tailnet as %s with %s", t.Subject, strings.Join(s.Tags, ",")), nil
}
