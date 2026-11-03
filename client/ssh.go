package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSH uses the native client, retaining its known-host verification and terminal handling.
func SSH(ctx context.Context, target, user string, args []string) error {
	if target == "" || strings.HasPrefix(target, "-") || user == "" {
		return errors.New("SSH target and user are required")
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	public, err := ssh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	result, err := Exchange(ctx, map[string]string{"audience": "ssh", "public_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))), "target": target, "user": user})
	if err != nil {
		return err
	}
	cert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(result.Certificate))
	if err != nil {
		return errors.New("invalid SSH certificate response")
	}
	typed, ok := cert.(*ssh.Certificate)
	if !ok || !strings.EqualFold(typed.Key.Type(), public.Type()) || string(typed.Key.Marshal()) != string(public.Marshal()) {
		return errors.New("SSH certificate is for a different key")
	}
	dir, err := os.MkdirTemp("", "romaine-ssh-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err = protectFile(dir); err != nil {
		return err
	}
	private, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return err
	}
	keyPath := filepath.Join(dir, "identity")
	certPath := keyPath + "-cert.pub"
	for path, data := range map[string][]byte{keyPath: pem.EncodeToMemory(private), certPath: []byte(result.Certificate + "\n")} {
		file, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		if e = protectFile(path); e != nil {
			file.Close()
			return e
		}
		_, e = file.Write(data)
		file.Close()
		if e != nil {
			return e
		}
	}
	binary := "/usr/bin/ssh"
	if runtime.GOOS == "windows" {
		binary = filepath.Join(os.Getenv("SystemRoot"), "System32", "OpenSSH", "ssh.exe")
	}
	argv := []string{"-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-i", keyPath, "-o", "CertificateFile=" + certPath, "-l", user, target}
	argv = append(argv, args...)
	cmd := exec.CommandContext(ctx, binary, argv...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("SSH: %w", err)
	}
	return nil
}
