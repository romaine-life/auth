package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os/exec"
	"strings"
)

func openPlatformKey(create bool) (signer, error) {
	cmd := exec.Command("/usr/bin/security", "find-generic-password", "-s", "romaine-machine", "-a", "machine-key", "-w")
	data, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if !create || !errors.As(err, &exit) || exit.ExitCode() != 44 {
			return nil, errors.New("macOS Keychain machine key is missing or locked")
		}
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, e
		}
		der, e := x509.MarshalECPrivateKey(key)
		if e != nil {
			return nil, e
		}
		// Interactive mode accepts the command on stdin, keeping key material out of argv.
		add := exec.Command("/usr/bin/security", "-i")
		add.Stdin = strings.NewReader("add-generic-password -s romaine-machine -a machine-key -w " + base64.StdEncoding.EncodeToString(der) + "\n")
		if e = add.Run(); e != nil {
			return nil, errors.New("cannot save machine credential in macOS Keychain")
		}
		// security's interactive exit status is not the individual command's status.
		check, e := exec.Command("/usr/bin/security", "find-generic-password", "-s", "romaine-machine", "-a", "machine-key", "-w").Output()
		if e != nil || !bytes.Equal(bytes.TrimSpace(check), []byte(base64.StdEncoding.EncodeToString(der))) {
			return nil, errors.New("Keychain did not save the machine credential")
		}
		return softwareSigner{key}, nil
	}
	der, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if e != nil {
		return nil, e
	}
	key, e := x509.ParseECPrivateKey(der)
	if e != nil {
		return nil, e
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("machine key is not P-256")
	}
	return softwareSigner{key}, nil
}
func publicJWK() (map[string]string, error) {
	s, e := openPlatformKey(false)
	if e != nil {
		return nil, e
	}
	defer s.Close()
	return ecPublicJWK(&s.(softwareSigner).k.PublicKey), nil
}
