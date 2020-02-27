package pals

import (
	"bytes"
	"crypto/aes"
	"log"
	"testing"
)

func TestEncryptDecryptCBC(t *testing.T) {
	ex := []struct {
		key   []byte
		iv    []byte
		input []byte
	}{
		{[]byte("Please test me!!"), []byte{0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3}, []byte("We all live in a yellow submarine, yellow subm..")},
		{[]byte("Dont Stop Me Now"), []byte{1, 2, 3, 4, 34, 78, 16, 1, 2, 2, 2, 2, 3, 3, 3, 3}, []byte("Cause we're having a good time..")},
	}

	for _, e := range ex {
		cypher, err := aes.NewCipher([]byte(e.key))
		if err != nil {
			log.Fatalf("failed to instantiate cypher with key %v: %v", e.key, err)
		}
		encrypter := NewCBCEncrypter(cypher, e.iv)
		decrypter := NewCBCDecrypter(cypher, e.iv)
		result := make([]byte, len(e.input))
		encrypter.CryptBlocks(result, e.input)
		decrypter.CryptBlocks(result, result)
		if !bytes.Equal(result, e.input) {
			t.Errorf("Encrypt-decrypt (key: %v, iv: %v) failed: \nInp: %v \nGot: %v", e.key, e.iv, e.input, result)
		}
	}
}
