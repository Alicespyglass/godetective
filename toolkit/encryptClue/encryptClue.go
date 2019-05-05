package main

import (
	"GODETECTIVE/toolkit/createHash"
	"GODETECTIVE/toolkit/decryptClue"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

func encrypt(data []byte, passphrase string) []byte {
	// create an AES block cipher with hashed passphrase
	key := []byte(createHash.Hash256(passphrase))
	block, _ := aes.NewCipher(key)

	// wrap block in Galois Counter Mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	// create a nonce of length specified by GCM
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	// Seal creates authenticated cipherText using a nonce and cipher block (data)
	// nonce used for decryption must be the same as one used in encryption
	// first paramter in Seal is a prefix value which encrypted data is appended to. We prepend nonce here
	// last paramter is for any additional data such as headers
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
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
	plaintext := decryptClue.Decrypt(ciphertext, "password")
	fmt.Printf("Decrypted: %s\n", plaintext)
	encryptFile("incriminatingEvidenceAgainstRichAndPowerfulPeople.txt", []byte("Hello World"), "password")
	fmt.Println(string(decryptClue.DecryptFile("incriminatingEvidenceAgainstRichAndPowerfulPeople.txt", "password")))
}
