package main

import (
	"crypto/aes"
	"fmt"
	"log"
)

// C7 solves set1, challenge 7
func C7() {
	const key = "YELLOW SUBMARINE"
	const dataPath = "set1c7data.txt"

	data, err := ReadAllBase64("set1c7data.txt")
	if err != nil {
		log.Fatalf("Failed to read data: %v", data)
	}
	cypher, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatalf("Failed to instantiate cypher with key %v: %v", key, data)
	}
	plain := make([]byte, len(data))
	cypher.Decrypt(plain, data)
	fmt.Printf("The plain text is:\n\n %v", plain)
}
