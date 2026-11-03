package client

import (
	"context"
	"errors"
	"os/exec"
)

func reloadSSH(ctx context.Context) error {
	if exec.CommandContext(ctx, "systemctl", "reload", "ssh.service").Run() == nil {
		return nil
	}
	if exec.CommandContext(ctx, "systemctl", "reload", "sshd.service").Run() == nil {
		return nil
	}
	return errors.New("SSH configuration installed but systemd could not reload ssh/sshd")
}
