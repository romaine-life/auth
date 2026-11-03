package client

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/ssh"
)

const userTrustStart = "# BEGIN auth.romaine.life account trust"
const userTrustEnd = "# END auth.romaine.life account trust"

func sshAuthorizedKeys(original string, key ssh.PublicKey, principals []string) (string, error) {
	var lines []string
	inBlock, seen := false, false
	for _, line := range strings.Split(strings.TrimSuffix(original, "\n"), "\n") {
		switch strings.TrimSuffix(line, "\r") {
		case userTrustStart:
			if inBlock || seen {
				return "", errors.New("duplicate managed SSH account trust block")
			}
			inBlock, seen = true, true
		case userTrustEnd:
			if !inBlock {
				return "", errors.New("incomplete managed SSH account trust block")
			}
			inBlock = false
		default:
			if !inBlock {
				lines = append(lines, line)
			}
		}
	}
	if inBlock {
		return "", errors.New("incomplete managed SSH account trust block")
	}
	body := strings.Join(lines, "\n")
	if body != "" && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	return body + userTrustStart + "\ncert-authority,principals=\"" + strings.Join(principals, ",") + "\" " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + "\n" + userTrustEnd + "\n", nil
}

// InstallSSHUserTrust authorizes only the named principals for the calling Unix
// account. Existing keys are retained and the system SSH configuration is untouched.
func InstallSSHUserTrust(ctx context.Context, user string, principals []string) error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return errors.New("account SSH trust requires macOS or Linux")
	}
	login, err := exec.CommandContext(ctx, "/usr/bin/id", "-un").Output()
	if err != nil {
		return errors.New("cannot determine current OS login")
	}
	if user != strings.TrimSpace(string(login)) {
		return errors.New("account SSH trust can only be installed for the current OS login")
	}
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	if err := validateSSHPrincipals(user, principals, hostname); err != nil {
		return err
	}
	key, err := fetchSSHCA(ctx)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	return writeSSHUserTrust(home, key, principals)
}

func writeSSHUserTrust(home string, key ssh.PublicKey, principals []string) error {
	dir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("SSH directory must be a real directory")
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, "authorized_keys")
	var original []byte
	if info, err = os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("authorized_keys must be a regular file")
		}
		original, err = os.ReadFile(path)
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	body, err := sshAuthorizedKeys(string(original), key, principals)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".romaine-trust-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err = temp.WriteString(body); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}
