package pals

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
// result slice. The two slices must be of equal length
func XorFixed(left []byte, right []byte) []byte {
	out := make([]byte, len(left))

	// TODO: better error handling
	if len(right) != len(left) {
		panic("cannot take xor of two different length buffers!")
	}
	// Could reuse an input buffer here
	for i := range left {
		out[i] = left[i] ^ right[i]
	}
	return out
}
