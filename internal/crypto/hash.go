package crypto

import (
	"crypto/sha256"
)

func HashAuthKey(authKey []byte) []byte {
	h := sha256.Sum256(authKey)
	return h[:]
}