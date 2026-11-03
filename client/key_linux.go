package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"github.com/99designs/keyring"
)

func openPlatformKey(create bool) (signer, error) {
	ring, err := keyring.Open(keyring.Config{ServiceName: "kdewallet", KWalletAppID: "romaine-machine", KWalletFolder: "romaine-machine", AllowedBackends: []keyring.BackendType{keyring.KWalletBackend, keyring.SecretServiceBackend}})
	if err != nil {
		return nil, err
	}
	item, err := ring.Get("machine-key")
	if err != nil {
		if !create || !errors.Is(err, keyring.ErrKeyNotFound) {
			return nil, err
		}
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, e
		}
		data, e := x509.MarshalECPrivateKey(key)
		if e != nil {
			return nil, e
		}
		if e = ring.Set(keyring.Item{Key: "machine-key", Data: data, Label: "Romaine machine credential"}); e != nil {
			return nil, e
		}
		return softwareSigner{key}, nil
	}
	key, err := x509.ParseECPrivateKey(item.Data)
	if err != nil {
		return nil, err
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
