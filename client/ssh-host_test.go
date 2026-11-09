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

func TestRemovingTheLastLoginRemovesAllMachineTrust(t *testing.T) {
	root := t.TempDir()
	original := "Subsystem sftp sftp-server.exe\n"
	config, err := SSHConfig(original, root)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "romaine-principals")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	put := func(path, data string) {
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	put(filepath.Join(root, "sshd_config"), config)
	put(filepath.Join(root, "romaine-ca.pub"), "ssh-ed25519 AAAA ca\n")
	put(filepath.Join(dir, "nelson"), "device:owner/mac@nelsonpc/nelson\n")
	put(filepath.Join(dir, "other"), "device:owner/mac@nelsonpc/other\n")
	var applied []string
	apply := func(path, before, after string) error {
		applied = append(applied, after)
		put(path, after)
		return nil
	}

	if err := removeHostTrust(root, "other", apply); err != nil {
		t.Fatal(err)
	}
	if logins, _ := installedLogins(root); !slices.Equal(logins, []string{"nelson"}) || len(applied) != 0 {
		t.Fatalf("removing one of two logins left %v and applied %d configs", logins, len(applied))
	}
	if _, err := os.Stat(filepath.Join(root, "romaine-ca.pub")); err != nil {
		t.Fatalf("CA key removed while a login still trusts it: %v", err)
	}

	if err := removeHostTrust(root, "nelson", apply); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(applied, []string{original}) {
		t.Fatalf("last removal applied %q, want the config without the trust block", applied)
	}
	for _, gone := range []string{filepath.Join(root, "romaine-ca.pub"), dir} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Fatalf("%s left after removing the last login: %v", gone, err)
		}
	}
	if logins, err := installedLogins(root); err != nil || len(logins) != 0 {
		t.Fatalf("installed logins after removal: %v, %v", logins, err)
	}
	if err := removeHostTrust(root, "nelson", apply); err != nil || len(applied) != 1 {
		t.Fatalf("removing trust that is already gone: %v, %d applies", err, len(applied))
	}
}
