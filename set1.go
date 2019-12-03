package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

const (
	hexTest    = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	c2LeftStr  = "1c0111001f010100061a024b53535009181c"
	c2RightStr = "686974207468652062756c6c277320657965"

	c3CypherText = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	c5Str        = "Burning 'em, if you ain't quick and nimble"
	//"I go crazy when I hear a cymbal"
	c5Key = "ICE"
	space = ' '
)

var (
	c3LetterFreq = map[rune]float32{
		' ': 13.00, // made up: space is slightly more frequent than E/e
		'e': 12.02,
		't': 9.10,
		'a': 8.12,
		'o': 7.68,
		'i': 7.31,
		'n': 6.95,
		's': 6.28,
		'r': 6.02,
		'h': 5.92,
		'd': 4.32,
		'l': 3.98,
		'u': 2.88,
		'c': 2.71,
		'm': 2.61,
		'f': 2.30,
		'y': 2.11,
		'w': 2.09,
		'g': 2.03,
		'p': 1.82,
		'b': 1.49,
		'v': 1.11,
		'k': 0.69,
		'x': 0.17,
		'q': 0.11,
		'j': 0.10,
		'z': 0.07,
	}
)

// Set1 solution
func Set1() {
	// Challenge 1
	c1, err := hexToBase64(hexTest)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(c1)

	// Challenge 2
	fmt.Println("----------- c2 -------------")
	c2Left, err := hex.DecodeString(c2LeftStr)
	c2Right, err := hex.DecodeString(c2RightStr)
	c2Res := xorFixed(c2Left, c2Right)
	fmt.Println(hex.EncodeToString(c2Res))

	// Challenge 3
	fmt.Println("----------- c3 -------------")
	c3Res, c3Key, err := decryptSingleXor(c3CypherText)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Key: %v, Result: %v\n", c3Key, c3Res)

	// Challenge 4
	fmt.Println("----------- c4 -------------")
	file, err := os.Open("set1c4data.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var bestScore float32
	var bestRes string
	for scanner.Scan() {
		txt := scanner.Text()
		res, key, err := decryptSingleXor(txt)
		if err != nil {
			log.Fatal(err)
		}
		if s := score(res); s > bestScore {
			bestScore = s
			bestRes = res
			fmt.Printf("New best res: '%v' decrypts to '%q' with key '%v' and score: %v\n", txt, res, key, score(res))
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Best result from 60 candidates: %v", bestRes)

	// Challenge 5
	fmt.Println("----------- c5 -------------")
	c5bytes := []byte(c5Str)
	c5Res, err := xor([]byte(c5Key), c5bytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(c5Res))

	// Challenge 6
	c6()
}

func c6() {
	fmt.Println("----------- c6 -------------")
	origBytes, err := ioutil.ReadFile("set1c6data.txt")
	if err != nil {
		log.Fatal("failed to read data file: ")
	}
	var decodedBytes = make([]byte, base64.StdEncoding.DecodedLen(len(origBytes)))
	count, err := base64.StdEncoding.Decode(decodedBytes, origBytes)
	if err != nil {
		log.Fatalf("decoding failed after %v bytes: ", count)
	}
	//fmt.Printf("Decoded bytes: %xv\n", decodedBytes)

	// Test hamming distance
	fmt.Printf("Hamming distance from '%v' to '%v': %v\n", "this is a test", "wokka wokka!!!",
		hammingDistance([]byte("this is a test"), []byte("wokka wokka!!!")))

	// Guess key size, take first and second i bytes and find
	// minimal normalized edit distance
	var nMin float32 = 255.0
	var keySize int = 0
	var nD float32 = 0.0
	for i := 2; i <= 40; i++ {
		first := decodedBytes[:i]
		second := decodedBytes[i : 2*i]
		nD = float32(hammingDistance(first, second) / i)
		fmt.Printf("Hamming distance %x to %x (keysize %v): %v [normalized from: %v]\n", first, second, i, nD, nD*float32(i))
		if nD < nMin {
			fmt.Printf("Found new minimal keysize %v: distance %v\n", i, nD)
			nMin = nD
			keySize = i
		}
	}

	// Break bytes into keysize blocks
	var blocks [][]byte
	for keySize < len(origBytes) {
		origBytes, blocks = origBytes[keySize:], append(blocks, origBytes[0:keySize:keySize])
	}
	fmt.Printf("Blocks are: %v\n", blocks)

	// transpose them
	tBlocks := make([][]byte, keySize)
	for i := 0; i < keySize; i++ {
		tBlocks[i] = make([]byte, len(blocks))
	}
	for i := 0; i < keySize; i++ {
		for j := range blocks {
			tBlocks[i][j] = blocks[j][i]
		}
	}
	fmt.Printf("Transposed blocks are: %v\n", tBlocks)

	// solve each block
	blockKeys := make([]int, keySize)
	blockRes := make([]string, keySize)
	var blockErr error
	for i, bl := range tBlocks {
		blockRes[i], blockKeys[i], blockErr = decryptSingleXorB(bl)
		if blockErr != nil {
			log.Fatalf("failed to decode block: %s", blockErr)
		}
		fmt.Printf("Solved block %v with key %v: %v\n", i, blockKeys[i], blockRes[i])
	}

	// Put together the key
	fullKey := make([]byte, len(blockKeys))
	for i := range blockKeys {
		fullKey[i] = byte(blockKeys[i])
	}
	fmt.Printf("Full key is: %v\n", fullKey)

	// Finally, decrypt
	result, err := xor([]byte(fullKey), decodedBytes)
	if err != nil {
		fmt.Printf("failed to decrypt message: %v", err)
	}
	fmt.Printf("Result is: %v", string(result))
}

func hexToBase64(hexString string) (string, error) {
	bytes, err := hex.DecodeString(hexTest)
	if err != nil {
		return "", err
	}
	b64 := base64.StdEncoding.EncodeToString(bytes)
	return b64, nil
}

// xorFixed takes two byte slices and produces the byte-by-byte
// result slice
func xorFixed(left []byte, right []byte) []byte {
	out := make([]byte, len(left))

	// Could reuse an input buffer here
	for i := range left {
		out[i] = left[i] ^ right[i]
	}
	return out
}

// decrypt an english plaintext string in hex encoding that has been
//  xor'd against a single by repeatedly guessing the key
// and giving back the best-looking result
func decryptSingleXor(cypherText string) (string, int, error) {
	cypherBytes, err := hex.DecodeString(cypherText)
	if err != nil {
		return "", 0, fmt.Errorf("failed to convert cyphertext into bytes: ")
	}

	return decryptSingleXorB(cypherBytes)
}

// Decrypt a slice of bytes that has been encrypted by
// xoring against a single byte repeatedly. This is done by
// guessing the key and giving back the result that is most
// likely to correspond to English plain text.
func decryptSingleXorB(cypherBytes []byte) (string, int, error) {
	var res string
	var maxScore float32
	var key int

	// guess from A->z ascii code points
	// xor string with trial byte
	// encode bytes into string
	// score string
	// return highest scoring
	for i := 41; i < 123; i++ {
		b := []byte{byte(i)}
		bytes, err := xor(b, cypherBytes)
		if err != nil {
			return "", 0, fmt.Errorf("failed to xor cypher bytes %v with key %v: ", cypherBytes, b)
		}
		trial := string(bytes)
		if s := score(trial); s > maxScore {
			fmt.Printf("Found new high score %v with key %v, giving result '%v'\n", s, i, trial)
			maxScore = s
			res = trial
			key = i
		}
	}
	return res, key, nil
}

// repeatedly xor the bytes in target one by one with those
// in key. Assumes target perfectly divides into key.
func xor(key []byte, target []byte) ([]byte, error) {
	if len(target)%len(key) != 0 {
		return nil, fmt.Errorf("the buffer to encode (len %v) does not perfectly divide by the key length (%v)",
			len(target), len(key))
	}

	out := make([]byte, len(target))
	for i := 0; i < len(target); i += len(key) {
		for j := range key {
			out[i+j] = target[i+j] ^ key[j]
		}
	}
	return out, nil
}

// score a string against the expectation that it's English
// plaintext, using letter frequency
func score(text string) float32 {
	// Simple metric: string score is the sum of
	// frequencies of a given character.
	// We normalize the string first by turning it to lower case
	normalized := strings.ToLower(text)
	var score float32 = 0
	for _, r := range normalized {
		if val, ok := c3LetterFreq[r]; ok == true {
			score += val
		}
	}
	return score
}

// Return the number of differing bits between two byte slices
// adapted from https://en.wikipedia.org/wiki/Hamming_distance#Algorithm_example
// Assumes len(left) == len(right), results bad or panic otherwise
func hammingDistance(left []byte, right []byte) int {
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

// guessKeySize will guess the size (length) of the 
// Given a byte slice, key size, take first and second i bytes and find
// minimal normalized edit distance
func guessKeySize(data []byte) {
	// Guess key size, take first and second i bytes and find
	// minimal normalized edit distance

	// TODO: FIXME
	
	// var nMin float32 = 255.0
	// var keySize int = 0
	// var nD float32 = 0.0
	// for i := 2; i <= 40; i++ {
	// 	first := decodedBytes[:i]
	// 	second := decodedBytes[i : 2*i]
	// 	nD = float32(hammingDistance(first, second) / i)
	// 	fmt.Printf("Hamming distance %x to %x (keysize %v): %v [normalized from: %v]\n", first, second, i, nD, nD*float32(i))
	// 	if nD < nMin {
	// 		fmt.Printf("Found new minimal keysize %v: distance %v\n", i, nD)
	// 		nMin = nD
	// 		keySize = i
	// 	}
	}
}