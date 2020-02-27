package pals

import (
	"bytes"
	"crypto/aes"
	"log"
	"testing"
)

func TestEncryptDecryptECB(t *testing.T) {
	ex := []struct {
		key   []byte
		input []byte
	}{
		{[]byte("Please test me!!"), []byte("We all live in a yellow submarine, yellow subm..")},
		{[]byte("Dont Stop Me Now"), []byte("Cause we're having a good time..")},
		{[]byte("YELLOW SUBMARINEYELLOW SUBMARINE"), []byte("YELLOW SUBMARINE")},
	}

	for _, e := range ex {
		cypher, err := aes.NewCipher([]byte(e.key))
		if err != nil {
			log.Fatalf("failed to instantiate cypher with key %v: %v", e.key, err)
		}
		encrypter := NewECBEncrypter(cypher)
		decrypter := NewECBDecrypter(cypher)
		result := make([]byte, len(e.input))
		encrypter.CryptBlocks(result, e.input)
		decrypter.CryptBlocks(result, result)
		if !bytes.Equal(result, e.input) {
			t.Errorf("Encrypt-decrypt (key: %v) failed: \nInp: %v \nGot: %v", e.key, e.input, result)
		}
	}
}
