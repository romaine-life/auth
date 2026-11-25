package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestTailnetAuthKeyTradesTheTokenForATaggedOneUseKey(t *testing.T) {
	var minted map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token-exchange":
			b, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(b))
			if form.Get("client_id") != "CID" || form.Get("jwt") != "JWT" {
				http.Error(w, "bad exchange", 401)
				return
			}
			w.Write([]byte(`{"access_token":"ACCESS"}`))
		case "/tailnet/-/keys":
			if r.Header.Get("Authorization") != "Bearer ACCESS" {
				http.Error(w, "no bearer", 401)
				return
			}
			json.NewDecoder(r.Body).Decode(&minted)
			w.Write([]byte(`{"key":"tskey-auth-x"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	TailscaleAPI = srv.URL
	tok := TailscaleToken{Token: "JWT", Subject: "machine:nelsonlaptop", Audience: "api.tailscale.com/CID"}
	key, err := TailnetAuthKey(context.Background(), tok, []string{"tag:spirelens-host"})
	if err != nil || key != "tskey-auth-x" {
		t.Fatalf("key %q, %v", key, err)
	}
	create := minted["capabilities"].(map[string]any)["devices"].(map[string]any)["create"].(map[string]any)
	if create["reusable"] != false || create["ephemeral"] != false || create["preauthorized"] != true {
		t.Errorf("key isn't one-use, durable and pre-approved: %v", create)
	}
	if tags := create["tags"].([]any); len(tags) != 1 || tags[0] != "tag:spirelens-host" {
		t.Errorf("tags %v", tags)
	}
	if _, err := TailnetAuthKey(context.Background(), tok, nil); err == nil {
		t.Error("an untagged node got a key")
	}
	bad := tok
	bad.Token = "WRONG"
	if _, err := TailnetAuthKey(context.Background(), bad, []string{"tag:x"}); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("a refused exchange: %v", err)
	}
}

func TestReadTailnetState(t *testing.T) {
	orig := TailscaleCommand
	defer func() { TailscaleCommand = orig }()
	TailscaleCommand = func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "status" {
			return []byte(`{"BackendState":"NeedsLogin"}`), nil
		}
		return []byte(`{"AdvertiseTags":["tag:spirelens-host"],"RouteAll":true,"ForceDaemon":true,"Hostname":""}`), nil
	}
	s, err := ReadTailnetState(context.Background())
	if err != nil || s.BackendState != "NeedsLogin" || !s.AcceptRoutes || !s.Unattended || len(s.Tags) != 1 {
		t.Fatalf("%+v, %v", s, err)
	}
}

func TestJoinLeavesARunningNodeAlone(t *testing.T) {
	orig := TailscaleCommand
	defer func() { TailscaleCommand = orig }()
	var calls [][]string
	TailscaleCommand = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, args)
		if args[0] == "status" {
			return []byte(`{"BackendState":"Running"}`), nil
		}
		return []byte(`{"AdvertiseTags":["tag:x"]}`), nil
	}
	msg, err := JoinTailnet(context.Background(), false)
	if err != nil || msg != "already on the tailnet" || len(calls) != 2 {
		t.Fatalf("%q, %v, %v", msg, err, calls)
	}
}
