package main

import "crypto/cipher"

type cbc struct {
	b         cipher.Block
	blockSize int
	iv        []byte
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

// NewCBCDecrypter returns an implementation of CBC decryption for
// a given block cipher and IV
func NewCBCDecrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	return (*cbcDecrypter)(newCBC(block, iv))
}

// NewCBCEncrypter returns an implementation of CBC encryption for
// a given block cipher and IV
func NewCBCEncrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	return (*cbcEncrypter)(newCBC(block, iv))
}

// BlockSize returns the block size of the cbc block cipher
func (c *cbcDecrypter) BlockSize() int {
	return c.blockSize
}

// BlockSize returns the block size of the cbc block cipher
func (c *cbcEncrypter) BlockSize() int {
	return c.blockSize
}

// CryptBlocks encrypts a number of blocks. The length of
// src must be a multiple of the block size. Dst and src must overlap
// entirely or not at all.
func (c *cbcEncrypter) CryptBlocks(dst, src []byte) {
	srcBlocks := ChunkBytes(src, c.b.BlockSize())
	dstBlocks := make([][]byte, len(srcBlocks))
	enc := make([]byte, c.blockSize)
	for i := range srcBlocks {
		// 1) take previous block (or iv), xor with current
		enc = XorFixed(c.iv, srcBlocks[i])
		// 2) Encrypt with block cipher
		c.b.Encrypt(dstBlocks[i], enc)
		// 3) Updated most recently seen crypt block
		c.iv = dstBlocks[i]
	}
	dst = UnchunkBytes(dstBlocks)
}

// CryptBlocks decrypts a number of blocks. The length of
// src must be a multiple of the block size. Dst and src must overlap
// entirely or not at all.
func (c *cbcDecrypter) CryptBlocks(dst, src []byte) {

	// For each block, we need to xor the decrypted data with the previous block's ciphertext (the iv).
	// To avoid making a copy each time, we loop over the blocks BACKWARDS.
	srcBlocks := ChunkBytes(src, c.b.BlockSize())
	dstBlocks := make([][]byte, len(srcBlocks))

	dec := make([]byte, c.blockSize)
	for i := len(srcBlocks) - 1; i >= 0; i-- {
		c.b.Decrypt(dec, srcBlocks[i])
		dstBlocks[i] = XorFixed() //TODO: IV?
	}
}
