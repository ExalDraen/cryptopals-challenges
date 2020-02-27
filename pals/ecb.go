package pals

import "crypto/cipher"

type ecb struct {
	b         cipher.Block
	blockSize int
}

type ecbDecrypter ecb
type ecbEncrypter ecb

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

// NewECBDecrypter returns an implementation of ECB decryption for
// a given block cipher
func NewECBDecrypter(block cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(block))
}

// NewECBEncrypter returns an implementation of ECB encryption for
// a given block cipher
func NewECBEncrypter(block cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(block))
}

// BlockSize returns the block size of the cbc block cipher
func (c *ecbDecrypter) BlockSize() int {
	return c.blockSize
}

// BlockSize returns the block size of the cbc block cipher
func (c *ecbEncrypter) BlockSize() int {
	return c.blockSize
}

// CryptBlocks decrypts a number of blocks. The length of
// src must be a multiple of the block size. Dst and src must overlap
// entirely or not at all.
func (c *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%c.blockSize != 0 {
		panic("input not full blocks")
	}
	if len(dst) < len(src) {
		panic("output smaller than input")
	}
	srcBlocks := ChunkBytes(src, c.b.BlockSize())
	dstBlocks := make([][]byte, len(srcBlocks))

	for i := range srcBlocks {
		dstBlocks[i] = make([]byte, c.blockSize)
		c.b.Decrypt(dstBlocks[i], srcBlocks[i])
	}
	//recombine and update dst block
	copy(dst, UnchunkBytes(dstBlocks))

}

// CryptBlocks encrypts a number of blocks. The length of
// src must be a multiple of the block size. Dst and src must overlap
// entirely or not at all.
func (c *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%c.blockSize != 0 {
		panic("input not full blocks")
	}
	if len(dst) < len(src) {
		panic("output smaller than input")
	}
	srcBlocks := ChunkBytes(src, c.b.BlockSize())
	dstBlocks := make([][]byte, len(srcBlocks))

	for i := range srcBlocks {
		dstBlocks[i] = make([]byte, c.blockSize)
		c.b.Encrypt(dstBlocks[i], srcBlocks[i])
	}
	//recombine and update dst block
	copy(dst, UnchunkBytes(dstBlocks))
}
