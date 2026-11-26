package client

// Azure access on approval (AUT-9): a machine asks auth.romaine.life for Azure access, an
// administrator approves it on auth.romaine.life, and while the grant lasts the machine's
// device-token exchange with audience "azure" returns a federation token that
// `az login --service-principal --federated-token` turns into Azure access as the
// azure-access managed identity (infra-bootstrap tofu/azure-access.tf).

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
	"time"
)

// AzureRequest is a request for Azure access and, once decided, its grant.
type AzureRequest struct {
	ID               string `json:"id"`
	Status           string `json:"status"` // pending, approved, denied, expired or revoked
	Device           string `json:"device"`
	Reason           string `json:"reason"`
	Minutes          int    `json:"minutes"`
	ApproveURL       string `json:"approve_url"`
	RequestExpiresAt int64  `json:"request_expires_at"`
	GrantExpiresAt   int64  `json:"grant_expires_at"`
	DecidedBy        string `json:"decided_by"`
}

// AzureToken is a federation token for the azure-access identity and where it signs in.
type AzureToken struct {
	Token          string `json:"token"`
	ExpiresAt      int64  `json:"expires_at"`
	ClientID       string `json:"client_id"`
	TenantID       string `json:"tenant_id"`
	GrantID        string `json:"grant_id"`
	GrantExpiresAt int64  `json:"grant_expires_at"`
}

// AzureWaitSeconds is how long each status request asks auth to hold it open for a decision;
// auth answers the moment the request is decided.
const AzureWaitSeconds = 10

// RequestAzureAccess files a request with this machine's token.
func RequestAzureAccess(ctx context.Context, reason string, minutes int) (AzureRequest, error) {
	var out AzureRequest
	token, err := ReadMachineToken(ConfigDir())
	if err != nil {
		return out, err
	}
	err = azureCall(ctx, "POST", BaseURL+"/api/azure-access/requests", token, map[string]any{"reason": reason, "minutes": minutes}, &out)
	return out, err
}

// WaitAzureAccess returns once the request is no longer pending, or ctx ends.
func WaitAzureAccess(ctx context.Context, id string) (AzureRequest, error) {
	for {
		var out AzureRequest
		token, err := ReadMachineToken(ConfigDir())
		if err != nil {
			return out, err
		}
		u := fmt.Sprintf("%s/api/azure-access/requests/%s?wait=%d", BaseURL, url.PathEscape(id), AzureWaitSeconds)
		if err := azureCall(ctx, "GET", u, token, nil, &out); err != nil {
			return out, err
		}
		if out.Status != "pending" {
			return out, nil
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
	}
}

// GetAzureToken asks auth for a federation token; auth refuses without an approved grant.
func GetAzureToken(ctx context.Context) (AzureToken, error) {
	var out AzureToken
	err := exchangeInto(ctx, map[string]string{"audience": "azure"}, &out)
	if err == nil && (out.Token == "" || out.ClientID == "" || out.TenantID == "") {
		err = errors.New("auth returned an incomplete Azure token")
	}
	return out, err
}

// azCommand runs the Azure CLI; tests replace it.
var azCommand = func(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "az", args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

// AzureLogin signs the Azure CLI in as the azure-access identity with the token.
func AzureLogin(ctx context.Context, t AzureToken) error {
	err := azCommand(ctx, "login", "--service-principal", "--username", t.ClientID, "--tenant", t.TenantID,
		"--federated-token", t.Token, "--allow-no-subscriptions", "--output", "none")
	if err != nil {
		return fmt.Errorf("az login: %w", err)
	}
	return nil
}

// azureCall sends a JSON request with the machine token and decodes a 200 answer; a refusal
// comes back as auth's own message.
func azureCall(ctx context.Context, method, u, bearer string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	res, err := requestClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &AuthError{Kind: "unreachable", Detail: "cannot reach auth.romaine.life: " + netDetail(err)}
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		var refusal struct {
			Error  string `json:"error"`
			Reason string `json:"reason"`
		}
		json.NewDecoder(io.LimitReader(res.Body, 16384)).Decode(&refusal)
		if refusal.Error == "" {
			refusal.Error = res.Status
		}
		return fmt.Errorf("auth refused (HTTP %d, %s): %s", res.StatusCode, refusal.Reason, refusal.Error)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(out)
}

// FormatUnix is a Unix time as local clock time, for messages.
func FormatUnix(t int64) string {
	return time.Unix(t, 0).Local().Format("3:04 PM")
}
