package pals

import (
	"crypto/aes"
	"fmt"
)

// AesDecryptECB decrypts the given data under the given key
// using AES in ECB mode. A copy is returned, the original
// slice is unmodified.
func AesDecryptECB(data, key []byte) ([]byte, error) {
	keySize := len(key)
	if len(data)%keySize != 0 {
		return nil, fmt.Errorf("failed to decrypt data: key (len %v) does not evenly divide data (len %v)", keySize, len(data))
	}
	cypher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate cypher with key %v: %v", key, err)
	}

	// Decrypt the data block by block using the key
	dst := make([]byte, len(data))
	encrypter := NewECBDecrypter(cypher)
	encrypter.CryptBlocks(dst, data)
	return dst, nil
}

// AesEncryptECB encrypts the given data under the given key
// using AES in ECB mode. A copy is returned, the original
// slice is unmodified.
func AesEncryptECB(data, key []byte) ([]byte, error) {
	keySize := len(key)
	if len(data)%keySize != 0 {
		return nil, fmt.Errorf("failed to encrypt data: key (len %v) does not evenly divide data (len %v)", keySize, len(data))
	}
	cypher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate cypher with key %v: %v", key, err)
	}

	// Encrypt the data block by block using the key
	dst := make([]byte, len(data))
	encrypter := NewECBEncrypter(cypher)
	encrypter.CryptBlocks(dst, data)
	return dst, nil
}
