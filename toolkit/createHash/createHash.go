package createhash

import (
	"crypto/sha256"
)

func Hash256(key string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return hasher.Sum(nil)
}
