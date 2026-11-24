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

var loginPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,63}$`)

// withoutTrustBlock returns sshd_config without the managed trust block.
func withoutTrustBlock(original string) (string, error) {
	body := strings.ReplaceAll(original, "\r\n", "\n")
	if start := strings.Index(body, trustStart); start >= 0 {
		end := strings.Index(body[start:], trustEnd)
		if end < 0 {
			return "", errors.New("incomplete managed SSH trust block")
		}
		body = body[:start] + body[start+end+len(trustEnd):]
		body = strings.TrimLeft(body, "\n")
	}
	return body, nil
}

// retiredGlimmungTrust is the hand-placed trust glimmung's remote-run harness used, which
// SpireLens dropped (SPIRELENS-101): its comment and two directives, naming auth-ca.pub
// and auth_principals\%u in sshd's own directory. It is removed rather than reconciled
// (ATR-2); anything else naming a CA or principals still stops the install.
func retiredGlimmungTrust(line, root string) bool {
	line = strings.TrimSpace(line)
	if line == "# auth.romaine.life is the sole SSH CA issuer (glimmung remote-host execution)" {
		return true
	}
	words := strings.Fields(line)
	if len(words) != 2 {
		return false
	}
	path := strings.ToLower(strings.ReplaceAll(strings.Trim(words[1], `"`), `\`, "/"))
	dir := strings.ToLower(strings.ReplaceAll(root, `\`, "/")) + "/"
	return (strings.EqualFold(words[0], "TrustedUserCAKeys") && path == dir+"auth-ca.pub") ||
		(strings.EqualFold(words[0], "AuthorizedPrincipalsFile") && path == dir+"auth_principals/%u")
}

func withoutRetiredTrust(body, root string) string {
	lines := strings.Split(body, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if !retiredGlimmungTrust(line, root) {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

func SSHConfig(original, root string) (string, error) {
	body, err := withoutTrustBlock(original)
	if err != nil {
		return "", err
	}
	body = withoutRetiredTrust(body, root)
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

var hostNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}$`)

// validateSSHPrincipals checks each principal is for this login and names this host:
// its full, short or .local name, or a name the caller gives it (--host), such as the
// home PC name callers reach a PC by when Windows calls it something else (ATR-2).
func validateSSHPrincipals(user string, principals []string, hostname string, names ...string) error {
	if !loginPattern.MatchString(user) || len(principals) == 0 {
		return errors.New("an OS user and explicit machine principals are required")
	}
	hostname = strings.ToLower(hostname)
	shortname := strings.Split(hostname, ".")[0]
	hosts := []string{hostname, shortname, shortname + ".local"}
	for _, name := range names {
		name = strings.ToLower(name)
		if !hostNamePattern.MatchString(name) {
			return errors.New("invalid host name")
		}
		hosts = append(hosts, name)
	}
	for _, p := range principals {
		if !regexp.MustCompile(`^device:[A-Za-z0-9_-]+/[a-z0-9-]+@[a-z0-9.-]+/[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`).MatchString(p) || !strings.HasSuffix(p, "/"+user) {
			return errors.New("invalid or mismatched SSH principal")
		}
		named := false
		for _, h := range hosts {
			named = named || strings.Contains(p, "@"+h+"/")
		}
		if !named {
			return errors.New("SSH principal names another host")
		}
	}
	return nil
}

func fetchSSHCA(ctx context.Context) (ssh.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", BaseURL+"/api/ssh/ca", nil)
	if err != nil {
		return nil, err
	}
	response, err := requestClient.Do(req)
	if err != nil {
		return nil, errors.New("cannot fetch auth's SSH CA public key")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, errors.New("auth's SSH CA is not configured")
	}
	ca, err := io.ReadAll(io.LimitReader(response.Body, 16384))
	if err != nil {
		return nil, err
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey(ca)
	if err != nil || len(strings.TrimSpace(string(rest))) != 0 || key.Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("invalid SSH CA public key")
	}
	return key, nil
}

// hostPaths gives the host's sshd configuration directory and sshd binary.
func hostPaths() (root, sshd string) {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "ssh"), filepath.Join(os.Getenv("SystemRoot"), "System32", "OpenSSH", "sshd.exe")
	}
	return "/etc/ssh", "/usr/sbin/sshd"
}

// hostLogin is the principals file name sshd looks up for an OS login (%u).
func hostLogin(user string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(user)
	}
	return user
}

// hostTrust is the host SSH trust wanted for one OS login: auth's CA key, the
// login's principals and the sshd_config block naming both.
type hostTrust struct {
	root, sshd, user string
	original, config string
	ca, principals   []byte
}

func wantedHostTrust(ctx context.Context, user string, principals []string, names ...string) (*hostTrust, error) {
	if err := requireHostAdmin(); err != nil {
		return nil, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	if err := validateSSHPrincipals(user, principals, hostname, names...); err != nil {
		return nil, err
	}
	t := &hostTrust{user: hostLogin(user), principals: []byte(strings.Join(principals, "\n") + "\n")}
	t.root, t.sshd = hostPaths()
	original, err := os.ReadFile(filepath.Join(t.root, "sshd_config"))
	if err != nil {
		return nil, err
	}
	t.original = string(original)
	if t.config, err = SSHConfig(t.original, t.root); err != nil {
		return nil, err
	}
	key, err := fetchSSHCA(ctx)
	if err != nil {
		return nil, err
	}
	t.ca = ssh.MarshalAuthorizedKey(key)
	return t, nil
}

// differences names each part of the installed trust that is not as wanted.
func (t *hostTrust) differences() []string {
	var d []string
	if ca, err := os.ReadFile(filepath.Join(t.root, "romaine-ca.pub")); err != nil || string(ca) != string(t.ca) {
		d = append(d, "SSH CA key")
	}
	if p, err := os.ReadFile(filepath.Join(t.root, "romaine-principals", t.user)); err != nil || string(p) != string(t.principals) {
		d = append(d, "principals for "+t.user)
	}
	if t.original != t.config {
		d = append(d, "sshd_config trust block")
	}
	return d
}

// SSHHostTrustDifferences reads the installed host trust for an OS login and
// names each part InstallSSHHostTrust would change; none means it is current.
// Like the install, it requires host administrator privileges.
func SSHHostTrustDifferences(ctx context.Context, user string, principals []string, names ...string) ([]string, error) {
	t, err := wantedHostTrust(ctx, user, principals, names...)
	if err != nil {
		return nil, err
	}
	return t.differences(), nil
}

// InstallSSHHostTrust requires host administrator privileges. Only explicit
// target-qualified machine principals are installed for the given OS login.
func InstallSSHHostTrust(ctx context.Context, user string, principals []string, names ...string) error {
	t, err := wantedHostTrust(ctx, user, principals, names...)
	if err != nil {
		return err
	}
	path := filepath.Join(t.root, "sshd_config")
	if err = os.MkdirAll(filepath.Join(t.root, "romaine-principals"), 0755); err != nil {
		return err
	}
	if err = protectHostPath(filepath.Join(t.root, "romaine-principals"), true); err != nil {
		return err
	}
	if err = writeHostFile(filepath.Join(t.root, "romaine-ca.pub"), t.ca); err != nil {
		return err
	}
	if err = writeHostFile(filepath.Join(t.root, "romaine-principals", t.user), t.principals); err != nil {
		return err
	}
	if t.original == t.config {
		return nil
	}
	backup := path + ".before-romaine"
	if _, err = os.Stat(backup); os.IsNotExist(err) {
		if err = os.WriteFile(backup, []byte(t.original), 0600); err != nil {
			return err
		}
	}
	if err = applySSHConfig(ctx, t.sshd, path, t.original, t.config); err != nil {
		return err
	}
	// The retired trust's files go once sshd no longer names them.
	if err = os.Remove(filepath.Join(t.root, "auth-ca.pub")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.RemoveAll(filepath.Join(t.root, "auth_principals"))
}

// InstalledSSHHostLogins names each OS login that has installed machine
// principals. Reading them requires host administrator privileges; a host
// with no principals directory has none, which anyone can see.
func InstalledSSHHostLogins() ([]string, error) {
	root, _ := hostPaths()
	if _, err := os.Stat(filepath.Join(root, "romaine-principals")); os.IsNotExist(err) {
		return nil, nil
	}
	if err := requireHostAdmin(); err != nil {
		return nil, err
	}
	return installedLogins(root)
}

func installedLogins(root string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(root, "romaine-principals"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var logins []string
	for _, entry := range entries {
		if entry.Type().IsRegular() && !strings.HasPrefix(entry.Name(), ".") {
			logins = append(logins, entry.Name())
		}
	}
	return logins, nil
}

// RemoveSSHHostTrust removes an OS login's machine principals. Removing the
// last login's also removes the sshd_config block and auth's CA key, leaving
// the host with no machine trust. It requires host administrator privileges.
func RemoveSSHHostTrust(ctx context.Context, user string) error {
	if err := requireHostAdmin(); err != nil {
		return err
	}
	root, sshd := hostPaths()
	return removeHostTrust(root, user, func(path, original, config string) error {
		return applySSHConfig(ctx, sshd, path, original, config)
	})
}

func removeHostTrust(root, user string, apply func(path, original, config string) error) error {
	if !loginPattern.MatchString(user) {
		return errors.New("an OS user is required")
	}
	dir := filepath.Join(root, "romaine-principals")
	if err := os.Remove(filepath.Join(dir, hostLogin(user))); err != nil && !os.IsNotExist(err) {
		return err
	}
	if logins, err := installedLogins(root); err != nil || len(logins) > 0 {
		return err
	}
	path := filepath.Join(root, "sshd_config")
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	config, err := withoutTrustBlock(string(original))
	if err != nil {
		return err
	}
	if config != string(original) {
		if err = apply(path, string(original), config); err != nil {
			return err
		}
	}
	for _, leftover := range []string{filepath.Join(root, "romaine-ca.pub"), dir} {
		if err = os.Remove(leftover); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// applySSHConfig checks a new sshd_config with sshd, writes it and reloads the
// listener, restoring the original if the reload fails.
func applySSHConfig(ctx context.Context, sshd, path, original, config string) error {
	temp, err := os.CreateTemp(filepath.Dir(path), "sshd-check-*")
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
	if err = writeHostFile(path, []byte(config)); err != nil {
		return err
	}
	if err = reloadSSH(ctx); err != nil {
		if rollback := writeHostFile(path, []byte(original)); rollback != nil {
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
