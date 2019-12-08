package main

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
