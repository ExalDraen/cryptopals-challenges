package main

import (
	"fmt"
	"log"
)

// C7 solves set1, challenge 7
func C7() {
	fmt.Println("---------------------- c7 ------------------------")
	const key = "YELLOW SUBMARINE"
	const dataPath = "set1c7data.txt"

	data, err := ReadAllBase64("set1c7data.txt")
	if err != nil {
		log.Fatalf("Failed to read data: %v", data)
	}

	plain, err := AesDecrypt(data, []byte(key))
	if err != nil {
		log.Fatalf("Couldn't decrypt: %v", data)
	}
	fmt.Printf("The plain text is:\n\n %v", string(plain))
}
