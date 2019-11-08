package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
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
	fmt.Printf("%v: %v\n", "weehee", score("weehee"))
	fmt.Printf("%v: %v\n", "I am the law", score("I am the law"))
	c3Res, c3Key, err := decryptSingleXor(c3CypherText)
	fmt.Printf("Key: %v, Result: %v\n", c3Key, c3Res)

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

// decrypt an english plaintext string that has been
//  xor'd against a single by repeatedly guessing the key
// and giving back the best-looking result
func decryptSingleXor(cypherText string) (string, int, error) {
	// guess from A->z ascii code points
	// xor string with trial byte
	// encode bytes into string
	// score string
	// return highest scoring
	var res string
	var max int
	var key int
	for i := 41; i < 123; i++ {
		b := []byte{byte(i)}
		bytes, err := xor(b, []byte(cypherText))
		if err != nil {
			return "", 0, fmt.Errorf("failed to xor cyphertext %v with key %v: ", cypherText, b)
		}
		trial := string(bytes)
		if s := score(trial); s > max {
			max = s
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
// plaintext.
func score(text string) int {
	// Simple metric:
	// 2 points for lowercase ascii
	// 1 point for uppercase and digits
	// 1 point for spaces
	// 0 for everything else
	score := 0
	for _, r := range text {
		switch {
		case (r >= 48 && r <= 90): // Uppercase or digit
			score++
		case r == space:
			score++
		case r >= 97 && r <= 122:
			score += 2
		}
	}
	return score
}

// The score of a single rune as given by the character
// frequency in the English language
// Frequency sequence is etaoinshrdlcumwfgypbvkjxqz as given
// by wikipedia. Spaces are most common, digits more common than a but
// less common than t
// func runeVal(rune r) {
// 	// dumb metric: value for given character is
// }
