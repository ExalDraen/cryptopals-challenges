package pals

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
	if len(iv) != block.BlockSize() {
		panic("NewCBCDecrypter: IV length must equal block size")
	}
	return (*cbcDecrypter)(newCBC(block, iv))
}

// NewCBCEncrypter returns an implementation of CBC encryption for
// a given block cipher and IV
func NewCBCEncrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != block.BlockSize() {
		panic("NewCBCEncrypter: IV length must equal block size")
	}
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
	if len(src)%c.blockSize != 0 {
		panic("input not full blocks")
	}
	if len(dst) < len(src) {
		panic("output smaller than input")
	}
	srcBlocks := ChunkBytes(src, c.b.BlockSize())
	dstBlocks := make([][]byte, len(srcBlocks))
	enc := make([]byte, c.blockSize)
	for i := range srcBlocks {
		// 1) take previous block (or iv), xor with current
		enc = XorFixed(c.iv, srcBlocks[i])
		// 2) Encrypt with block cipher
		dstBlocks[i] = make([]byte, c.blockSize)
		c.b.Encrypt(dstBlocks[i], enc)
		// 3) Updated iv to be the most recently seen crypt block
		c.iv = dstBlocks[i]
	}
	copy(dst, UnchunkBytes(dstBlocks))
}

// CryptBlocks decrypts a number of blocks. The length of
// src must be a multiple of the block size. Dst and src must overlap
// entirely or not at all.
func (c *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%c.blockSize != 0 {
		panic("input not full blocks")
	}
	if len(dst) < len(src) {
		panic("output smaller than input")
	}
	srcBlocks := ChunkBytes(src, c.b.BlockSize())
	dstBlocks := make([][]byte, len(srcBlocks))

	// For each block, we need to xor the decrypted data with the previous block's ciphertext. (the iv).
	dec := make([]byte, c.blockSize)
	// To avoid making a copy each time, we loop over the blocks BACKWARDS.
	// when we reach the first block, we need to use the IV instead of the ciphertext, so treat
	// that case specially
	for i := len(srcBlocks) - 1; i > 0; i-- {
		c.b.Decrypt(dec, srcBlocks[i])
		dstBlocks[i] = XorFixed(dec, srcBlocks[i-1]) //TODO: IV
	}
	c.b.Decrypt(dec, srcBlocks[0])
	dstBlocks[0] = XorFixed(dec, c.iv)

	//recombine and update dst block
	copy(dst, UnchunkBytes(dstBlocks))
}
