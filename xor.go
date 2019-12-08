package main

// RepeatingKeyXOR returns a new slice containing
// the bytes in the data sliced repeatedly XORd against
// the slices in the key slice.
// The input data slice is not modified.
func RepeatingKeyXOR(data, key []byte) (out []byte) {
	out = make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}

	return
}

// XorFixed takes two byte slices and produces the byte-by-byte
// result slice
func XorFixed(left []byte, right []byte) []byte {
	out := make([]byte, len(left))

	// Could reuse an input buffer here
	for i := range left {
		out[i] = left[i] ^ right[i]
	}
	return out
}
