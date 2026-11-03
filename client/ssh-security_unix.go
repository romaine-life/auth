//go:build linux || darwin

package client

import (
	"errors"
	"os"
)

func requireHostAdmin() error {
	if os.Geteuid() != 0 {
		return errors.New("SSH host setup requires root")
	}
	return nil
}
func protectHostPath(path string, directory bool) error {
	mode := os.FileMode(0644)
	if directory {
		mode = 0755
	}
	return os.Chmod(path, mode)
}
