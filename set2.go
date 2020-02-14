package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
)

// CryptMode represents the block cypher mode
type CryptMode byte

// EncryptionFn represents an unknown function that encrypts bytes
// in block cypher mode
type EncryptionFn func([]byte) []byte

const (
	// CBCMode is Cypher Block Chaining (CBC) mode
	CBCMode CryptMode = iota
	// ECBMode is Electronic Code Book (ECB) mode
	ECBMode
)

// AES key size used throughout
const keySize = 16

// Set2 solutions
func Set2() {
	C9()
	C10()
	C11()
	C12()
}

var c12Key []byte

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
		guess := DetectCBCorECBData(crypt)
		fmt.Printf("%v: correct? %v \t[guess: %v, actual: %v]\n", i, mode == guess, guess, mode)
	}

}

// C12 solution
func C12() {
	fmt.Println("---------------------- c12 ------------------------")
	var result []byte

	blockSize, err := DiscoverBlockSize(RandomEncryptECB)
	if err != nil {
		log.Fatalf("couldn't discover block size: %v", err)
	}
	fmt.Printf("Found block size: %v\n", blockSize)

	mode := DetectCBCorECBFn(RandomEncryptECB)
	fmt.Printf("Found encryption mode: %v\n", mode)

	n, err := DiscoverNumBlocks(RandomEncryptECB)
	if err != nil {
		log.Fatalf("couldn't discover number of blocks: %v", err)
	}
	for i := 0; i < n; i++ {
		result = append(result, decryptBlock(blockSize, i, RandomEncryptECB)...)
	}
	fmt.Printf("Decrypted blocks: %v", string(result))
}

func decryptBlock(blockSize int, blockNum int, crypter EncryptionFn) []byte {
	// How to decrypt a block by block
	// ==========  Block 0 ===========
	// Round 1

	// (1) construct block   A A A A A A A
	// (2) feed in,          A A A A A A A P     P is the first byte of plaintext we want
	// (3) encrypt, get back X X X X X X X X

	// (4) generate all      A A A A A A A G(i)  G(i) is generated 0-255 byte
	// (5) this gives        Y Y Y Y Y Y Y Y
	// (6) find i where X = Y, => G(i) = P

	// Round 2

	// construct block   A A A A A A
	// feed in,          A A A A A A P Q     Q => second byte of plaintext
	// encrypt, get back X X X X X X X X

	// generate all      A A A A A A P G(i)  G(i) is generated 0-255 byte
	// this gives        Y Y Y Y Y Y Y Y
	// find i where X = Y, => G(i) = Q
	// (...)
	// repeat until entire block decrypted

	// ==========  Block 1 ===========
	// similar to above:
	// (1) construct block   A A A A A A A
	// (2) feed in,          A A A A A A A K K K K K K K P     K is known plaintext from above, P is byte we want
	// (3) encrypt, get back               X X X X X X X X

	// (4) generate all      A A A A A A A G(i)  G(i) is generated 0-255 byte
	// (5) this gives        Y Y Y Y Y Y Y Y
	// (6) find i where X = Y, => G(i) = P

	// (...)
	// repeat until all blocks decrypted
	var answer []byte
	var candidate []byte
	var cryptCandidate []byte
	candidates := make(map[string]string)

	// i tracks how many bytes to chop off the block we feed into the encryption fn
	for i := 1; i <= blockSize; i++ {
		feed := bytes.Repeat([]byte("A"), blockSize-i)
		crypt := ChunkBytes(RandomEncryptECB(feed), blockSize)[blockNum] //TODO: fragile, will blow up if wrong blockNum passed

		// generate candidates
		for i := 0; i < 256; i++ {
			candidate = append(feed, answer...)
			candidate = append(candidate, byte(i))
			cryptCandidate = ChunkBytes(RandomEncryptECB(candidate), blockSize)[blockNum]
			candidates[string(cryptCandidate)] = string(candidate)
		}

		// match = AAA + known plaintext + new plaintext byte
		match, ok := candidates[string(crypt)]
		if !ok {
			log.Fatalf("Couldn't find match for %v", crypt)
		}
		answer = append(answer, byte(match[len(match)-1]))
	}
	return answer
}

// DiscoverNumBlocks finds the number of encrypted blocks
// returned if the given encryption function is fed with
// just shy of one block
func DiscoverNumBlocks(crypter EncryptionFn) (int, error) {
	blockSize, err := DiscoverBlockSize(RandomEncryptECB)
	if err != nil {
		return 0, fmt.Errorf("failed to discover block size: %v", err)
	}

	// encrypt just under one block
	feed := bytes.Repeat([]byte("A"), blockSize-1)
	crypt := RandomEncryptECB(feed)
	return len(ChunkBytes(crypt, blockSize)), nil
}

// DiscoverBlockSize finds the size of the cypher blocks
// that the given encryption function uses
// Do this by repeatedly increasing the input until the return size changes
func DiscoverBlockSize(crypter EncryptionFn) (int, error) {
	var initLen, nextLen int // lengths of crypt text
	const maxSize = 2048
	var inp []byte

	initLen = len(crypter([]byte{}))
	for i := 1; i <= maxSize; i++ {
		inp = bytes.Repeat([]byte("A"), i)
		nextLen = len(crypter(inp))
		if nextLen > initLen {
			return nextLen - initLen, nil
		}
	}
	return 0, fmt.Errorf("unable to find block size, went to max: %v", maxSize) //
}

// RandomEncryptECB encrypts a given byte slice under a random
// but consistent key with an unknown suffix
func RandomEncryptECB(input []byte) []byte {
	const suffix = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

	if c12Key == nil {
		var err error
		c12Key, err = GenerateRandomBytes(keySize)
		if err != nil {
			log.Fatalf("unable to generate random bytes: %v", err)
		}
	}

	// prep plaintext
	suffixBytes, err := base64.StdEncoding.DecodeString(suffix)
	if err != nil {
		log.Fatal("could not decode suffix bytes")
	}
	var plaintext []byte
	plaintext = append(input, suffixBytes...)
	plaintext = PadPKCS7(plaintext, keySize)

	cypher, err := aes.NewCipher(c12Key)
	if err != nil {
		log.Fatalf("Failed to initialize cypher with key %v", c12Key)
	}
	dst := make([]byte, len(plaintext))
	encrypter := NewECBEncrypter(cypher)
	encrypter.CryptBlocks(dst, plaintext)

	return dst
}

// RandomEncryptCBCorECB encrypts the given byte slice with AES
// using a random key, and randomly choosing between CBC and ECB mode
func RandomEncryptCBCorECB(input []byte) ([]byte, CryptMode) {
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

// DetectCBCorECBData detects whether a given byte slice was
// encoded in CBC or ECB mode
func DetectCBCorECBData(data []byte) CryptMode {

	// guess if it's ECB mode by spotting repeating patterns, otherwise guess CBC
	score := ScoreECB(data)
	if score > 0 {
		return ECBMode
	}
	return CBCMode
}

// DetectCBCorECBFn detects whether or not the given encryption function
// encrypts in ECB or CBC mode.
// It does this by feeding a well-known, long input into the function
// and looking for repeats
func DetectCBCorECBFn(cryptFn EncryptionFn) CryptMode {
	// input must have at least one repeating block for us to be able to
	// detect ECB
	input := bytes.Repeat([]byte("F"), 1024)

	return DetectCBCorECBData(input)
}
