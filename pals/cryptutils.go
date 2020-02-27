package pals

// ScoreECB will score the likelihood of a given byte slice containing
// cypher text of a given block size, encrypted in ECB.
// It returns the number of blocks that repeated within the byte slice.
//
// ECB will encrypt the same plaintext to the same cyphertext
// so 16 byte blocks will repeat / show patterns.
// therefore: create histogram of byte blocks
// if there's multiple repeats
func ScoreECB(data []byte) int {
	const keySize = 16 // in bytes

	var chunk string
	var endScore int
	scores := make(map[string]int)

	for i := 0; i < len(data); i += keySize {
		chunk = string(data[i : i+keySize])
		scores[chunk]++
	}

	for _, v := range scores {
		if v > 1 {
			endScore++
		}
	}
	return endScore
}
