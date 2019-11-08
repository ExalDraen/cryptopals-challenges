package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
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
}

func hexToBase64(hexString string) (string, error) {
	bytes, err := hex.DecodeString(hexTest)
	if err != nil {
		return "", err
	}
	b64 := base64.StdEncoding.EncodeToString(bytes)
	return b64, nil
}

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
	// guess from A->z ascii code points
	// xor string with trial byte
	// encode bytes into string
	// score string
	// return highest scoring
	var res string
	var maxScore float32
	var key int

	cypherBytes, err := hex.DecodeString(cypherText)
	if err != nil {
		return "", 0, fmt.Errorf("failed to convert cyphertext into bytes: ")
	}
	//fmt.Printf("Cypher bytes are: %v \n", cypherBytes)
	for i := 41; i < 123; i++ {
		b := []byte{byte(i)}
		bytes, err := xor(b, cypherBytes)
		if err != nil {
			return "", 0, fmt.Errorf("failed to xor cyphertext %v with key %v: ", cypherText, b)
		}
		trial := string(bytes)
		if s := score(trial); s > maxScore {
			//fmt.Printf("Found new high score %v with key %v, giving result '%v'\n", s, i, trial)
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
