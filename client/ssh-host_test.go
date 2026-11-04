package client

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestInstalledHostTrustReportsNoDifferences(t *testing.T) {
	root := t.TempDir()
	config, err := SSHConfig("Subsystem sftp sftp-server.exe\n", root)
	if err != nil {
		t.Fatal(err)
	}
	want := &hostTrust{root: root, user: "nelson", original: config, config: config, ca: []byte("ssh-ed25519 AAAA ca\n"), principals: []byte("device:owner/nelsonpc@nelsonpc/nelson\n")}
	if err := os.MkdirAll(filepath.Join(root, "romaine-principals"), 0755); err != nil {
		t.Fatal(err)
	}
	put := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(root, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	put("romaine-ca.pub", want.ca)
	put(filepath.Join("romaine-principals", "nelson"), want.principals)
	if d := want.differences(); len(d) != 0 {
		t.Fatalf("installed trust matching the wanted trust reported %v", d)
	}
	put("romaine-ca.pub", []byte("ssh-ed25519 BBBB rotated\n"))
	put(filepath.Join("romaine-principals", "nelson"), []byte("device:owner/old@nelsonpc/nelson\n"))
	stale := *want
	stale.original = "Subsystem sftp sftp-server.exe\n"
	if d := stale.differences(); !slices.Equal(d, []string{"SSH CA key", "principals for nelson", "sshd_config trust block"}) {
		t.Fatalf("drifted trust reported %v", d)
	}
	if err := os.Remove(filepath.Join(root, "romaine-ca.pub")); err != nil {
		t.Fatal(err)
	}
	if d := want.differences(); !slices.Contains(d, "SSH CA key") {
		t.Fatalf("missing CA key reported %v", d)
	}
}
