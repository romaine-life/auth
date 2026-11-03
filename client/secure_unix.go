//go:build linux || darwin

package client

import "os"

func protectFile(path string) error { return os.Chmod(path, 0600) }
