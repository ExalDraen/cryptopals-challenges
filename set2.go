package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"math/rand"
)

// CryptMode represents the block cypher mode
type CryptMode byte

const (
	// CBCMode is Cypher Block Chaining (CBC) mode
	CBCMode CryptMode = iota
	// ECBMode is Electronic Code Book (ECB) mode
	ECBMode
)

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

// C11 solution
func C11() {
	fmt.Println("---------------------- c11 ------------------------")

}

// RandomEncryptCBCorECB encrypts the given byte slice with AES
// using a random key, and randomly choosing between CBC and ECB mode
func RandomEncryptCBCorECB(input []byte) ([]byte, CryptMode) {
	const keySize = 16 // for now, we hardcode this
	// pick ecb or cbc
	var mode CryptMode
	if rand.Intn(2) == 0 {
		mode = ECBMode
	} else {
		mode = CBCMode
	}
	// generate random key / iv
	key, err := GenerateRandomBytes(keySize)
	if err != nil {
		log.Fatalf("couldn't generate key length %v", keySize)
	}
	iv, err := GenerateRandomBytes(keySize) // not used for ECB mode but who cares
	if err != nil {
		log.Fatalf("couldn't generate IV length %v", keySize)
	}

	// append & prepend 5-10 bytes
	// TODO: pre/postpend should be one random byte, repeated
	pre, err := GenerateRandomBytes(5 + rand.Intn(5))
	if err != nil {
		log.Fatal("couldn't generate prepend bytes")
	}
	app, err := GenerateRandomBytes(5 + rand.Intn(5))
	if err != nil {
		log.Fatal("couldn't generate prepend bytes")
	}

	var plaintext []byte
	plaintext = append(plaintext, app...)
	plaintext = append(pre, plaintext...)

	// TODO: pad plaintext to keySize boundary

	// encrypt
	var encrypter cipher.BlockMode
	cypher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Failed to initialize cypher with key %v", key)
	}
	dst := make([]byte, len(plaintext))
	if mode == CBCMode {
		encrypter = NewCBCDecrypter(cypher, iv)
		encrypter.CryptBlocks(dst, plaintext)
	} else {
		encrypter = NewECBDecrypter(cypher)
		encrypter.CryptBlocks(dst, plaintext)
	}
	return dst, mode
}

// DetectCBCorECBMode detects whether a given byte slice was
// encoded in CBC or ECB mode
func DetectCBCorECBMode(data []byte) CryptMode {

	// guess if it's ECB mode by spotting repeating patterns, otherwise guess CBC
	return ECBMode
}
