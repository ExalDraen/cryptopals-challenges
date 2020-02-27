package main

import (
	"fmt"
	"log"
	"sort"

	"github.com/ExalDraen/cryptopals-challenges/pals"
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
			dist += float64(pals.HammingDistance(a, b))
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

// solveWithSize attempts to decrypt a byte slice
// encoded with repeating key xor of a given size
// assuming the plain text is English ASCII.
func solveWithSize(size int, data []byte) []byte {
	fmt.Printf("Solving data of len %v with a key length %v (%v blocks)\n", len(data), size, len(data)/size)

	// Break bytes into keysize blocks
	blocks := pals.ChunkBytes(data, size)
	//fmt.Printf("Blocks are: %v\n", blocks)

	// transpose them
	tBlocks := pals.Transpose(blocks)
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
		//fmt.Printf("The %v character in each key block is [key byte: %v]: %v\n", i, blockKeys[i], blockRes[i])
	}

	// Could simply output the transposed solved blocks here, but
	// for sake of following the instructions, reconstruct the key
	// instead

	// Put together the key
	fullKey := make([]byte, len(blockKeys))
	for i := range blockKeys {
		fullKey[i] = byte(blockKeys[i])
	}
	fmt.Printf("Full key is: %v\n", fullKey)

	// Finally, decrypt
	result := pals.RepeatingKeyXOR(data, []byte(fullKey))
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
	fmt.Printf("Hamming distance of '%v' to '%v': %v\n", hTest1, hTest2, pals.HammingDistance([]byte(hTest1), []byte(hTest2)))

	original, err := pals.ReadAllBase64(dataPath)
	if err != nil {
		log.Fatalf("Failed to read C6 input %v", err)
	}
	fmt.Printf("Decoded encoded data into %v bytes of data\n", len(original))

	// Get possible key sizes
	candidates := KeysFromB(original, 2, 50)

	// Decrypt with a few key sizes from the most likely to the least likely
	for i := 0; i < sizesToTry && i < len(candidates); i++ {
		plaintext := solveWithSize(candidates[i].length, original)
		fmt.Printf("Plain text solution at size %v:\n\n %v\n", candidates[i].length, string(plaintext))
	}

}
