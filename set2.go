package main

import "fmt"

import "crypto/aes"

import "log"

// Set2 solutions
func Set2() {
	C9()
	C10()
}

// C9 solutions
func C9() {
	fmt.Println("---------------------- c9 ------------------------")
	const trial = "YELLOW SUBMARINE"
	fmt.Printf("Trial %v padded to 20: %q\n", trial, string(PadPKCS7([]byte(trial), 20)))
}

// C10 solution
func C10() {
	fmt.Println("---------------------- c10 ------------------------")
	const key = "YELLOW SUBMARINE"
	const iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

	cypher, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatalf("failed to instantiate cypher with key %v: %v", key, err)
	}
	decrypter := NewCBCDecrypter(cypher, []byte(iv))

	orig, err := ReadAllBase64("c10data.txt")
	if err != nil {
		log.Fatalf("failed to read file: %v", err)
	}
	fmt.Printf("\nOriginal bytes: %v", orig)
	decrypted := make([]byte, len(orig))
	decrypter.CryptBlocks(decrypted, orig)
	fmt.Printf("\nDecrypted bytes, as string: %v", string(decrypted))
}
