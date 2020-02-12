package main

import (
	"bytes"
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
	C11()
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
	// input must have at least one repeating block for us to be able to
	// detect ECB
	input := bytes.Repeat([]byte("F"), 128)

	for i := 0; i < 8; i++ {
		crypt, mode := RandomEncryptCBCorECB([]byte(input))
		guess := DetectCBCorECBMode(crypt)
		fmt.Printf("%v: correct? %v \t[guess: %v, actual: %v]\n", i, mode == guess, guess, mode)
	}

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
	plaintext = append(input, app...)
	plaintext = append(pre, plaintext...)

	// pad plaintext to keySize boundary
	plaintext = PadPKCS7(plaintext, keySize)

	// encrypt
	var encrypter cipher.BlockMode
	cypher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Failed to initialize cypher with key %v", key)
	}
	dst := make([]byte, len(plaintext))
	if mode == CBCMode {
		encrypter = NewCBCEncrypter(cypher, iv)
		encrypter.CryptBlocks(dst, plaintext)
	} else {
		encrypter = NewECBEncrypter(cypher)
		encrypter.CryptBlocks(dst, plaintext)
	}
	return dst, mode
}

// DetectCBCorECBMode detects whether a given byte slice was
// encoded in CBC or ECB mode
func DetectCBCorECBMode(data []byte) CryptMode {

	// guess if it's ECB mode by spotting repeating patterns, otherwise guess CBC
	score := ScoreECB(data)
	if score > 0 {
		return ECBMode
	}
	return CBCMode
}
