package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestAccountTrustPreservesKeysAndRestrictsPrincipals(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(pub)
	user := "nromai01@stellarus.com"
	principal := "device:owner/nelsonpc@fl7vg4g5ww.local/" + user
	if err := validateSSHPrincipals(user, []string{principal}, "FL7VG4G5WW.local"); err != nil {
		t.Fatal(err)
	}
	if err := validateSSHPrincipals(user, []string{principal}, "FL7VG4G5WW"); err != nil {
		t.Fatal(err)
	}
	original := "# personal keys\nssh-ed25519 existing-key keep-this\n"
	body, err := sshAuthorizedKeys(original, key, []string{principal})
	if err != nil || !strings.HasPrefix(body, original) {
		t.Fatalf("existing keys changed: %v", err)
	}
	parsed, _, options, _, err := ssh.ParseAuthorizedKey([]byte(strings.Split(body, "\n")[3]))
	if err != nil || string(parsed.Marshal()) != string(key.Marshal()) || len(options) != 2 || options[0] != "cert-authority" || options[1] != "principals=\""+principal+"\"" {
		t.Fatalf("incorrect CA restrictions: %v %v", options, err)
	}
	again, err := sshAuthorizedKeys(body, key, []string{principal})
	if err != nil || again != body {
		t.Fatal("account trust is not idempotent")
	}
	for _, bad := range []string{"device:owner/nelsonpc@other/" + user, principal + ",root", principal + "\n", "device:owner/nelsonpc@fl7vg4g5ww.local/root"} {
		if validateSSHPrincipals(user, []string{bad}, "fl7vg4g5ww.local") == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	for _, bad := range []string{userTrustStart + "\n", userTrustEnd + "\n", body + body} {
		if _, err = sshAuthorizedKeys(bad, key, []string{principal}); err == nil {
			t.Fatal("accepted malformed managed block")
		}
	}
}

func TestAccountTrustWritesAtomicallyAndRefusesSymlinks(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Unix account trust")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(pub)
	home := t.TempDir()
	dir := filepath.Join(home, ".ssh")
	os.Mkdir(dir, 0700)
	path := filepath.Join(dir, "authorized_keys")
	original := "personal-key\n"
	os.WriteFile(path, []byte(original), 0644)
	if err := writeSSHUserTrust(home, key, []string{"principal"}); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	got, _ := os.ReadFile(path)
	if info.Mode().Perm() != 0600 || !strings.HasPrefix(string(got), original) {
		t.Fatal("permissions or existing keys were lost")
	}
	os.Remove(path)
	outside := filepath.Join(home, "other")
	os.WriteFile(outside, []byte("unchanged"), 0600)
	os.Symlink(outside, path)
	if writeSSHUserTrust(home, key, []string{"principal"}) == nil {
		t.Fatal("followed authorized_keys symlink")
	}
	got, _ = os.ReadFile(outside)
	if string(got) != "unchanged" {
		t.Fatal("modified symlink target")
	}
}
