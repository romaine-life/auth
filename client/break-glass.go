package client

// Break-glass on approval (AHT-209): a Claude session asks auth.romaine.life for a grant, an
// administrator approves it on auth.romaine.life, and while it lasts owner-guard lets that
// session past, and the machine's device-token exchange with audience
// "home-cluster-break-glass" returns a token the home cluster takes as cluster-admin.
// It shares Azure access's calls (azure.go): the same machine token, held status requests and
// refusals.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// BreakGlassAudience is the device-token exchange's audience for the cluster token.
const BreakGlassAudience = "home-cluster-break-glass"

// BreakGlassRequest is a break-glass request and, once decided, its grant. Times are Unix
// seconds.
type BreakGlassRequest struct {
	ID               string `json:"id"`
	Status           string `json:"status"` // pending, approved, denied, expired or revoked
	Device           string `json:"device"`
	Session          string `json:"session"`
	Reason           string `json:"reason"`
	Minutes          int    `json:"minutes"`
	ApproveURL       string `json:"approveUrl"`
	RequestExpiresAt int64  `json:"requestExpiresAt"`
	GrantExpiresAt   int64  `json:"grantExpiresAt"`
	DecidedBy        string `json:"decidedBy"`
}

// BreakGlassGrant is one of this machine's active grants.
type BreakGlassGrant struct {
	ID             string `json:"id"`
	Session        string `json:"session"`
	GrantExpiresAt int64  `json:"grantExpiresAt"`
}

// ClusterToken is the home cluster's break-glass token and the grant it rides on.
type ClusterToken struct {
	Token          string `json:"token"`
	ExpiresAt      int64  `json:"expires_at"`
	Device         string `json:"device"`
	GrantID        string `json:"grant_id"`
	Session        string `json:"session"`
	GrantExpiresAt int64  `json:"grant_expires_at"`
}

// RequestBreakGlass files a request for the Claude session with this machine's token.
func RequestBreakGlass(ctx context.Context, reason, session string, minutes int) (BreakGlassRequest, error) {
	var out BreakGlassRequest
	token, err := ReadMachineToken(ConfigDir())
	if err != nil {
		return out, err
	}
	err = azureCall(ctx, "POST", BaseURL+"/api/break-glass/requests", token,
		map[string]any{"reason": reason, "minutes": minutes, "session": session}, &out)
	return out, err
}

// WaitBreakGlass returns once the request is no longer pending, or ctx ends.
func WaitBreakGlass(ctx context.Context, id string) (BreakGlassRequest, error) {
	for {
		var out BreakGlassRequest
		token, err := ReadMachineToken(ConfigDir())
		if err != nil {
			return out, err
		}
		u := fmt.Sprintf("%s/api/break-glass/requests/%s?wait=%d", BaseURL, url.PathEscape(id), AzureWaitSeconds)
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

// ActiveBreakGlass lists this machine's approved, unexpired, unrevoked grants.
func ActiveBreakGlass(ctx context.Context) ([]BreakGlassGrant, error) {
	var out []BreakGlassGrant
	token, err := ReadMachineToken(ConfigDir())
	if err != nil {
		return nil, err
	}
	err = azureCall(ctx, "GET", BaseURL+"/api/break-glass/active", token, nil, &out)
	return out, err
}

// SessionBreakGlass is the session's active grant, the longest-lasting if it has several,
// or nil when it has none.
func SessionBreakGlass(ctx context.Context, session string) (*BreakGlassGrant, error) {
	grants, err := ActiveBreakGlass(ctx)
	if err != nil {
		return nil, err
	}
	var found *BreakGlassGrant
	for i := range grants {
		if grants[i].Session == session && (found == nil || grants[i].GrantExpiresAt > found.GrantExpiresAt) {
			found = &grants[i]
		}
	}
	return found, nil
}

// GetClusterToken asks auth for the home cluster's break-glass token; auth refuses without
// an active grant. It is never cached, so a revoke stops the next kubectl call.
func GetClusterToken(ctx context.Context) (ClusterToken, error) {
	var out ClusterToken
	err := exchangeInto(ctx, map[string]string{"audience": BreakGlassAudience}, &out)
	if err == nil && (out.Token == "" || out.ExpiresAt == 0) {
		err = errors.New("auth returned an incomplete cluster token")
	}
	return out, err
}

// ExecCredential is the token as a kubeconfig exec plugin answers kubectl
// (client.authentication.k8s.io/v1).
func ExecCredential(t ClusterToken) ([]byte, error) {
	return json.Marshal(map[string]any{
		"apiVersion": "client.authentication.k8s.io/v1",
		"kind":       "ExecCredential",
		"status": map[string]string{
			"token":               t.Token,
			"expirationTimestamp": time.Unix(t.ExpiresAt, 0).UTC().Format(time.RFC3339),
		},
	})
}
