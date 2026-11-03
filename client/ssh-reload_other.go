//go:build !windows && !linux && !darwin

package client

import (
	"context"
	"errors"
)

func reloadSSH(context.Context) error {
	return errors.New("SSH host setup is unavailable on this platform")
}
func requireHostAdmin() error            { return errors.New("unsupported SSH host platform") }
func protectHostPath(string, bool) error { return errors.New("unsupported SSH host platform") }
