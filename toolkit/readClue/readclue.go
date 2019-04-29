package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	filename := os.Args[1]
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "couldn't read file. Err: %v", err)
	}
	fmt.Printf("Reading file: \n%s", data)
}
