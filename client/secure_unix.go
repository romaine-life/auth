//go:build linux || darwin

package client

import "os"

func protectFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := os.FileMode(0600)
	if info.IsDir() {
		mode = 0700
	}
	return os.Chmod(path, mode)
}
