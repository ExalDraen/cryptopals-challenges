package pals

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
)

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

// HammingDistance returns the number of differing bits between two byte slices
// adapted from https://en.wikipedia.org/wiki/Hamming_distance#Algorithm_example
// Assumes len(left) == len(right), results bad or panic otherwise
func HammingDistance(left []byte, right []byte) int {
	dist := 0
	for idx, l := range left {
		r := right[idx]
		for val := l ^ r; val > 0; val /= 2 {
			if val&1 == 1 {
				dist++
			}
		}
	}
	return dist
}

// ChunkBytes split a slice of bytes into a slice containing
// slices of `size` bytes. If the original slice does not evenly
// divide into `size` any remainder bytes are dropped.
func ChunkBytes(data []byte, size int) (blocks [][]byte) {
	for size <= len(data) {
		data, blocks = data[size:], append(blocks, data[0:size:size])
	}
	return
}

// UnchunkBytes concatnates a slice of byte slices into a single
// slice of bytes
func UnchunkBytes(blocks [][]byte) (data []byte) {
	for i := range blocks {
		data = append(data, blocks[i]...)
	}
	return
}

// ReadAllBase64 reads bas64 encoded test from the given file
// and returns the decoded output as a byte slice
func ReadAllBase64(path string) ([]byte, error) {
	// Read and base64 decode data
	enc, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read data file: %v", err)
	}
	out, err := base64.StdEncoding.DecodeString(string(enc))
	if err != nil {
		return nil, fmt.Errorf("decoding failed: %v", err)
	}
	return out, nil
}

// GenerateRandomBytes generates Generates `n` random bytes
// Not cryptographically secure.
func GenerateRandomBytes(n int) ([]byte, error) {
	result := make([]byte, n)
	_, err := rand.Read(result)
	if err != nil {
		return []byte{}, err
	}
	return result, nil
}
