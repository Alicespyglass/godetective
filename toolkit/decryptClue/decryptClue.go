package decryptClue

import (
	"GODETECTIVE/toolkit/createHash"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/ioutil"
)

func Decrypt(data []byte, passphrase string) []byte {
	// 1. Create a cryptographic hash with the passphrase
	key := []byte(createHash.Hash256(passphrase))
	fmt.Printf("1. hash key: %x\n", key)

	// 2. Create an AES block cipher with the hash
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("2. aes cipher block: %x\n", block)

	// 3. Wrap block in Galois Counter Mode
	gcm, err := cipher.NewGCM(block)
	fmt.Printf("3. gcm: %v\n", gcm)
	if err != nil {
		panic(err.Error())
	}

	// 4. Remember we'd prefixed the nonce with the data. Now separate from ciphertext
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	fmt.Printf("4a. nonce: %v\n", nonce)
	fmt.Printf("4b. ciphertext: %x\n", nonce)

	// 5. Decrypt data to plaintext with Open and the nonce and ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("5. plaintext: %x\n", plaintext)
	return plaintext
}

func DecryptFile(filename string, passphrase string) []byte {
	data, _ := ioutil.ReadFile(filename)
	return Decrypt(data, passphrase)
}
