package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"sort"
)

// Candidate is a key length candidate
type Candidate struct {
	length int
	score  float64
}

// KeysFromB returns a sorted list of possible XoR key sizes
// given a slice of bytes. The range of sizes from-to is checked
// and keys are ranked based on the hamming distance of successive
// sets of bytes from the byte slice
func KeysFromB(data []byte, from int, to int) []Candidate {
	// Store candidates in a simple array
	var candidates []Candidate
	var dist float64
	var normalized float64

	// Guess key size, take first and second i bytes and find
	// minimal normalized edit distance
	for size := from; size < to; size++ {
		dist = 0.0
		normalized = 0.0

		// We need 4 blocks to compare, so if we don't have those, bail
		if len(data) < 4*size {
			continue
		}

		// compare successive blocks of size i and find out their normalized hamming distance
		iters := (len(data) / size) - 1 // we are looking 1 block ahead
		for j := 0; j < iters; j++ {
			a := data[j*size : (j+1)*size : (j+1)*size]
			b := data[(j+1)*size : (j+2)*size : (j+2)*size]
			dist += float64(HammingDistance(a, b))
		}
		normalized = dist / float64(iters) / float64(size)
		candidates = append(candidates, Candidate{length: size, score: normalized})
	}
	// Reverse Sort candidates by hamming distance (i.e. minimal distance first)
	//fmt.Printf("Raw key length candidates: %+v\n", candidates)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score < candidates[j].score
	})
	//fmt.Printf("Sorted candidates: %+v\n", candidates)

	return candidates
}

// Transpose transpose a slice of slices of bytes,
// e.g. turning a 5x10 slice into a 10x5 slice,
func Transpose(data [][]byte) (tBlocks [][]byte) {
	size := len(data[0]) // length of slices within slices
	tBlocks = make([][]byte, size)
	for i := 0; i < size; i++ {
		tBlocks[i] = make([]byte, len(data))
	}
	for i := 0; i < size; i++ {
		for j := range data {
			tBlocks[i][j] = data[j][i]
		}
	}
	return
}

// ChunkBytes split a slice of bytes into a slice containing
// slices of `size` bytes
func ChunkBytes(data []byte, size int) (blocks [][]byte) {
	//var blocks [][]byte
	// dataClone := make([]byte, len(data))
	// copy(dataClone, data)
	for size < len(data) {
		data, blocks = data[size:], append(blocks, data[0:size:size])
	}
	return
}

// solveWithSize attempts to decrypt a byte slice
// encoded with repeating key xor of a given size
// assuming the plain text is English ASCII.
func solveWithSize(size int, data []byte) []byte {
	fmt.Printf("Solving data of len %v with a key length %v (%v blocks)\n", len(data), size, len(data)/size)

	// Break bytes into keysize blocks
	blocks := ChunkBytes(data, size)
	//fmt.Printf("Blocks are: %v\n", blocks)

	// transpose them
	tBlocks := Transpose(blocks)
	//fmt.Printf("Transposed blocks are: %v\n", tBlocks)

	// solve each block
	blockKeys := make([]int, size)
	blockRes := make([]string, size)
	blockResBytes := make([][]byte, size)
	var blockErr error
	for i, bl := range tBlocks {
		blockRes[i], blockKeys[i], blockErr = DecryptSingleXorB(bl)
		blockResBytes[i] = []byte(blockRes[i])
		if blockErr != nil {
			log.Fatalf("failed to decode transposed block: %s", blockErr)
		}
		fmt.Printf("The %v character in each key block is [key byte: %v]: %v\n", i, blockKeys[i], blockRes[i])
	}

	// transpose the solved blocks back
	solvedBytes := bytes.Join(Transpose(blockResBytes), []byte{})
	fmt.Printf("*** Solution ***:\n%s\n", solvedBytes)

	// Put together the key
	fullKey := make([]byte, len(blockKeys))
	for i := range blockKeys {
		fullKey[i] = byte(blockKeys[i])
	}
	fmt.Printf("Full key is: %v\n", fullKey)

	// Finally, decrypt
	result, err := xor([]byte(fullKey), data)
	if err != nil {
		log.Fatalf("failed to decrypt message: %v", err)
	}
	return result
}

// C6 - solution to challenge 6
func C6() {
	const hTest1 = "this is a test"
	const hTest2 = "wokka wokka!!!"
	const dataPath = "./set1c6data.txt"
	const sizesToTry = 1

	fmt.Println("---------------------- c6 ------------------------")
	// Verify hamming distance implementation is correct
	fmt.Printf("Hamming distance of '%v' to '%v': %v\n", hTest1, hTest2, HammingDistance([]byte(hTest1), []byte(hTest2)))

	// Read and base64 decode data
	enc, err := ioutil.ReadFile(dataPath)
	if err != nil {
		log.Fatal("failed to read data file: ")
	}
	fmt.Printf("Read %v bytes of base64 data\n", len(enc))
	original, err := base64.StdEncoding.DecodeString(string(enc))
	if err != nil {
		log.Fatalf("decoding failed: %v", err)
	}
	fmt.Printf("Decoded encoded data into %v bytes of data\n", len(original))

	// Get possible key sizes
	candidates := KeysFromB(original, 2, 50)

	// Decrypt with a few key sizes from the most likely to the least likely
	for i := 0; i < sizesToTry && i < len(candidates); i++ {
		plaintext := solveWithSize(candidates[i].length, original)
		fmt.Printf("Plain text solution at size %v: %v\n", candidates[i].length, string(plaintext))
	}

}
