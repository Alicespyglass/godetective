package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/ioutil"
	"os"

	// Phil: use full github name for packages so they're go-gettable
	"github.com/alicespyglass/godetective/toolkit/createhash"
)

func decrypt(data []byte, passphrase string) []byte {
	// 1. Create a cryptographic hash with the passphrase
	key := createhash.Hash256(passphrase)
	fmt.Printf("1. hash key: %x\n", key)

	// 2. Create an AES block cipher with the hash
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("2. aes cipher block: %x\n", block)

	// 3. Wrap block in Galois Counter Mode
	gcm, err := cipher.NewGCM(block)
	fmt.Printf("3. gcm: %v\n", gcm)
	if err != nil {
		panic(err)
	}

	// 4. Remember we'd prefixed the nonce with the data. Now separate from ciphertext
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	fmt.Printf("4a. nonce: %v\n", nonce)
	fmt.Printf("4b. ciphertext: %x\n", nonce)

	// 5. Decrypt data to plaintext with Open and the nonce and ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("5. plaintext: \n%s\n", plaintext)
	return plaintext
}

func decryptFile(filename string, passphrase string) []byte {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't read file. Err: %v", err)
	}
	// Phil: %x to match what you have showing the data on the encrypt side
	fmt.Printf("Encrypted data: \n%x\n", data)
	return decrypt(data, passphrase)
}

func main() {
	fmt.Println("Starting decryption...")
	filename := os.Args[1]
	passphrase := os.Args[2]
	decryptFile(filename, passphrase)
}
