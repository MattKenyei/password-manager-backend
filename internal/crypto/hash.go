package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

func HashAuthKey(authKey []byte) []byte {
	h := sha256.Sum256(authKey)
	return h[:]
}

func GenerateRefreshToken() (raw []byte, hash []byte, err error) {
	raw = make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return nil, nil, fmt.Errorf("generate refresh token %w", err)
	}
	h := sha256.Sum256(raw)
	return raw, h[:], nil
}

func hashToken(raw []byte) []byte {
	h := sha256.Sum256(raw)
	return h[:]
}
