package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func createHash(key string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	fmt.Printf("v hash.Sum base16: %x\n", hasher.Sum(nil))
	return hasher.Sum(nil)
}

func encrypt(data []byte, passphrase string) []byte {
	// create an AES block cipher with hashed passphrase
	key := []byte(createHash(passphrase))
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

func decrypt(data []byte, passphrase string) []byte {
	// create an AES block cipher with hashed passphrase
	key := []byte(createHash(passphrase))
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

func encryptFile(filename string, data []byte, passphrase string) {
	f, _ := os.Create(filename)
	defer f.Close()
	f.Write(encrypt(data, passphrase))
}

func decryptFile(filename string, passphrase string) []byte {
	data, _ := ioutil.ReadFile(filename)
	return decrypt(data, passphrase)
}

func main() {
	fmt.Println("Starting the application...")
	ciphertext := encrypt([]byte("Hello World"), "password")
	fmt.Printf("Encrypted: %v\n", ciphertext)
	plaintext := decrypt(ciphertext, "passwor1")
	fmt.Printf("Decrypted: %s\n", plaintext)
	encryptFile("incriminatingEvidenceAgainstRichAndPowerfulPeople.txt", []byte("Hello World"), "password")
	fmt.Println(string(decryptFile("incriminatingEvidenceAgainstRichAndPowerfulPeople.txt", "password")))
}
