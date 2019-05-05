package createHash

import (
	"crypto/sha256"
	"fmt"
)

func Hash256(key string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	fmt.Printf("v hash.Sum base16: %x\n", hasher.Sum(nil))
	return hasher.Sum(nil)
}
