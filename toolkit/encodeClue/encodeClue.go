package main

import (
	"fmt"
	"hash/crc32"
	"os"
)

func main() {
	rawSecret := os.Args[1:]
	// rawString := strings.Join(rawSecret[:], ",")
	codedSecret := crc32.NewIEEE()
	fmt.Fprintf(codedSecret, rawSecret[0])
	fmt.Printf("hash=%#x", codedSecret.Sum32())
}
