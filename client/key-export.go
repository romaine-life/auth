package client

import (
	"crypto/ecdsa"
	"encoding/base64"
)

func ecPublicJWK(k *ecdsa.PublicKey) map[string]string {
	x, y := make([]byte, 32), make([]byte, 32)
	k.X.FillBytes(x)
	k.Y.FillBytes(y)
	return map[string]string{"kty": "EC", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y)}
}
