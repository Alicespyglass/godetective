package decryptClue

import (
	"GODETECTIVE/toolkit/createHash"
	"crypto/aes"
	"crypto/cipher"
	"io/ioutil"
)

func Decrypt(data []byte, passphrase string) []byte {
	// create an AES block cipher with hashed passphrase
	key := []byte(createHash.Hash256(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// wrap block in Galois Counter Mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	// create a nonce of length specified by GCM.
	// remember we'd prefixed the nonce with the data. Now separate from ciphertext
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// decrypt data with Open and return as plaintext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func DecryptFile(filename string, passphrase string) []byte {
	data, _ := ioutil.ReadFile(filename)
	return Decrypt(data, passphrase)
}
