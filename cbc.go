package main

import "crypto/cipher"

type cbc struct {
	b  cipher.Block
	iv []byte
}

// NewCBCDecrypter returns an implementation of CBC for
// a given block cipher and IV
func NewCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {

	return nil
}
