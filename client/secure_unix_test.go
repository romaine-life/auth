//go:build linux || darwin

package client

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateSSHDirectoryRemainsTraversable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ssh")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := protectFile(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("private directory must permit owner traversal: %v, %v", info, err)
	}
	key := filepath.Join(dir, "identity")
	if err := os.WriteFile(key, []byte("fixture"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := protectFile(key); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(key)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private key must be owner-only: %v, %v", info, err)
	}
	if _, err := os.ReadFile(key); err != nil {
		t.Fatal(err)
	}
}

func TestHomeTokenCacheIsPrivate(t *testing.T) {
	issuingFixture(t, 300)
	if _, err := HomeToken(context.Background(), "shows"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(homeTokenPath("shows"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("the cached token must be private: %v, %v", info, err)
	}
}
