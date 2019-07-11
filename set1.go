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
	c5Str      = "Burning 'em, if you ain't quick and nimble"
	//"I go crazy when I hear a cymbal"
	c5Key = "ICE"
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
	fmt.Println("------------------------")
	c2Left, err := hex.DecodeString(c2LeftStr)
	c2Right, err := hex.DecodeString(c2RightStr)
	c2Res := xorFixed(c2Left, c2Right)
	fmt.Println(hex.EncodeToString(c2Res))

	// Challenge 5
	fmt.Println("------------------------")
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
