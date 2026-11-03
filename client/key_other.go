//go:build !windows && !linux && !darwin

package client

import "errors"

func openPlatformKey(bool) (signer, error) {
	return nil, errors.New("machine authentication is available on Windows, macOS and Linux")
}
func publicJWK() (map[string]string, error) {
	return nil, errors.New("machine authentication is unavailable on this platform")
}
func protectFile(string) error {
	return errors.New("credential storage is unavailable on this platform")
}
