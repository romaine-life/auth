package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const trustStart = "# BEGIN auth.romaine.life machine trust"
const trustEnd = "# END auth.romaine.life machine trust"

func SSHConfig(original, root string) (string, error) {
	body := strings.ReplaceAll(original, "\r\n", "\n")
	if start := strings.Index(body, trustStart); start >= 0 {
		end := strings.Index(body[start:], trustEnd)
		if end < 0 {
			return "", errors.New("incomplete managed SSH trust block")
		}
		body = body[:start] + body[start+end+len(trustEnd):]
		body = strings.TrimLeft(body, "\n")
	}
	for _, line := range strings.Split(body, "\n") {
		words := strings.Fields(line)
		if len(words) == 0 {
			continue
		}
		if strings.EqualFold(words[0], "TrustedUserCAKeys") || strings.EqualFold(words[0], "AuthorizedPrincipalsFile") {
			return "", errors.New("existing SSH CA/principal configuration must be reconciled before installing machine trust")
		}
	}
	path := strings.ReplaceAll(root, "\\", "/")
	return trustStart + "\nTrustedUserCAKeys \"" + path + "/romaine-ca.pub\"\nAuthorizedPrincipalsFile \"" + path + "/romaine-principals/%u\"\n" + trustEnd + "\n" + body, nil
}

// InstallSSHHostTrust requires host administrator privileges. Only explicit
// target-qualified machine principals are installed for the given OS login.
func InstallSSHHostTrust(ctx context.Context, user string, principals []string) error {
	if err := requireHostAdmin(); err != nil {
		return err
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`).MatchString(user) || len(principals) == 0 {
		return errors.New("an OS user and explicit machine principals are required")
	}
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	hostname = strings.ToLower(hostname)
	for _, p := range principals {
		if !regexp.MustCompile(`^device:[A-Za-z0-9_-]+/[a-z0-9-]+@[a-z0-9.-]+/[A-Za-z0-9._-]+$`).MatchString(p) || !strings.HasSuffix(p, "/"+user) {
			return errors.New("invalid or mismatched SSH principal")
		}
		if !strings.Contains(p, "@"+hostname+"/") && !strings.Contains(p, "@"+strings.Split(hostname, ".")[0]+"/") {
			return errors.New("SSH principal names another host")
		}
	}
	root := "/etc/ssh"
	sshd := "/usr/sbin/sshd"
	if runtime.GOOS == "windows" {
		root = filepath.Join(os.Getenv("ProgramData"), "ssh")
		sshd = filepath.Join(os.Getenv("SystemRoot"), "System32", "OpenSSH", "sshd.exe")
		user = strings.ToLower(user)
	}
	path := filepath.Join(root, "sshd_config")
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	config, err := SSHConfig(string(original), root)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", BaseURL+"/api/ssh/ca", nil)
	response, err := requestClient.Do(req)
	if err != nil {
		return errors.New("cannot fetch auth's SSH CA public key")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("auth's SSH CA is not configured")
	}
	ca, err := io.ReadAll(io.LimitReader(response.Body, 16384))
	if err != nil {
		return err
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey(ca)
	if err != nil || len(strings.TrimSpace(string(rest))) != 0 || key.Type() != ssh.KeyAlgoED25519 {
		return errors.New("invalid SSH CA public key")
	}
	if err = os.MkdirAll(filepath.Join(root, "romaine-principals"), 0755); err != nil {
		return err
	}
	if err = protectHostPath(filepath.Join(root, "romaine-principals"), true); err != nil {
		return err
	}
	if err = writeHostFile(filepath.Join(root, "romaine-ca.pub"), ssh.MarshalAuthorizedKey(key)); err != nil {
		return err
	}
	if err = writeHostFile(filepath.Join(root, "romaine-principals", user), []byte(strings.Join(principals, "\n")+"\n")); err != nil {
		return err
	}
	if string(original) == config {
		return nil
	}
	temp, err := os.CreateTemp(root, "sshd-check-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err = temp.WriteString(config); err != nil {
		temp.Close()
		return err
	}
	temp.Close()
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(checkCtx, sshd, "-t", "-f", temp.Name()).CombinedOutput(); err != nil {
		return fmt.Errorf("SSH configuration refused: %s", strings.TrimSpace(string(out)))
	}
	backup := path + ".before-romaine"
	if _, err = os.Stat(backup); os.IsNotExist(err) {
		if err = os.WriteFile(backup, original, 0600); err != nil {
			return err
		}
	}
	if err = writeHostFile(path, []byte(config)); err != nil {
		return err
	}
	if err = reloadSSH(ctx); err != nil {
		if rollback := writeHostFile(path, original); rollback != nil {
			return fmt.Errorf("SSH reload and config restore failed: %w", rollback)
		}
		recovery, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if recoveryErr := reloadSSH(recovery); recoveryErr != nil {
			return fmt.Errorf("SSH config restored but listener recovery failed: %w", recoveryErr)
		}
		return fmt.Errorf("SSH config restored after reload failure: %w", err)
	}
	return nil
}

func writeHostFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".ssh-trust-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = protectHostPath(file.Name(), false); err != nil {
		file.Close()
		return err
	}
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
