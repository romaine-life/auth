package client

import (
	"context"
	"os"
	"testing"
)

func TestPersonalBrowserFlowLive(t *testing.T) {
	if os.Getenv("ROMAINE_PERSONAL_LOGIN_LIVE") != "1" {
		t.Skip("explicit interactive Windows browser verification only")
	}
	credentials, err := HumanLogin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ParseClaims(credentials.Token)
	if err != nil || !IsHuman(claims) {
		t.Fatal("browser flow did not return a separate personal identity")
	}
	t.Log("native Windows browser flow returned a personal identity")
}
