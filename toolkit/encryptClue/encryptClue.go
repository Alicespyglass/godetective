package main

import (
	"GODETECTIVE/toolkit/createHash"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

func encrypt(data []byte, passphrase string) []byte {
	// 1. Create a cryptographic hash with the passphrase
	key := []byte(createHash.Hash256(passphrase))
	fmt.Printf("1. hash key: %x\n", key)

	// 2. Create an AES block cipher with the hash
	block, _ := aes.NewCipher(key)
	fmt.Printf("2. aes cipher block: %x\n", block)

	// 3. Wrap block in Galois Counter Mode
	gcm, err := cipher.NewGCM(block)
	fmt.Printf("3. gcm: %v\n", gcm)
	if err != nil {
		panic(err.Error())
	}

	// 4. create a nonce of length specified by GCM
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	fmt.Printf("4. nonce: %v\n", nonce)

	// 5. Seal creates authenticated cipherText using a nonce and cipher block (data).
	// Nonce used for decryption must be the same as one used in encryption.
	// First paramter in Seal is a prefix value which encrypted data is appended to. We prepend nonce here.
	// Last paramter is for any additional data such as headers.
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	fmt.Printf("5. ciphertext: %x\n", ciphertext)
	return ciphertext
}

func encryptFile(filename string, data []byte, passphrase string) {
	f, _ := os.Create(filename)
	defer f.Close()
	f.Write(encrypt(data, passphrase))
}

func main() {
	fmt.Println("Starting the application...")
	ciphertext := encrypt([]byte("Hello World"), "password")
	fmt.Printf("Encrypted: %v\n", ciphertext)
}
