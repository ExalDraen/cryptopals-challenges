package main

import "crypto/cipher"

type cbc struct {
	b   cipher.Block
	cur []byte
	iv  []byte
}

type cbcDecrypter cbc
type cbcEncrypter cbc

func newCBC(b cipher.Block, iv []byte) *cbc {
	return &cbc{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        iv,
	}
}

// NewCBCDecrypter returns an implementation of CBC for
// a given block cipher and IV
func NewCBCDecrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	return (*cbcDecrypter)(newCBC(block, iv))
}

func NewCBCEncrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	return (*cbcEncrypter)(newCBC(block, iv))
}

func NewCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	return &cbcDecrypter{
		b:   b,
		iv:  iv,
		cur: iv,
	}
}

// BlockSize returns the block size of the cbc block cipher
func (c *cbcDecrypter) BlockSize() int {
	return c.b.BlockSize()
}

// CryptBlocks encrypts or decrypts a number of blocks. The length of
// src must be a multiple of the block size. Dst and src must overlap
// entirely or not at all.
func (c *cbcDecrypter) CryptBlocks(dst, src []byte) {
	srcBlocks := ChunkBytes(src, c.b.BlockSize())
	dstBlocks := make([][]byte, len(srcBlocks))
	for i := range srcBlocks {
		// 1) take previous block (or iv), xor with current
		enc := XorFixed(c.cur, srcBlocks[i])
		// 2) Encrypt with block cipher
		c.b.Encrypt(dstBlocks[i], enc)
		// 3) Updated most recently seen crypt block
		c.cur = dstBlocks[i]
	}
	dst = UnchunkBytes(dstBlocks)
}
