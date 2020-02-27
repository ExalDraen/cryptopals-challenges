package pals

import (
	"crypto/aes"
	"fmt"
)

// AesDecryptECB decrypts a given set of data that was encrypted
// with AES in ECB.
// The original data is not modified.
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
	plain := make([]byte, len(data))
	for i := 0; i < len(data); i += keySize {
		cypher.Decrypt(plain[i:i+keySize], data[i:i+keySize])
	}
	return plain, nil
}

// AesEncryptECB encrypts a given set of data
// with a given key. No padding is done.
// The original data is not modified.
func AesEncryptECB(data, key []byte) ([]byte, error) {
	keySize := len(key)
	if len(data)%keySize != 0 {
		return nil, fmt.Errorf("failed to encrypt data: key (len %v) does not evenly divide data (len %v)", keySize, len(data))
	}
	cypher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate cypher with key %v: %v", key, err)
	}

	// Encrypt the data block by block using the key
	crypt := make([]byte, len(data))
	for i := 0; i < len(data); i += keySize {
		cypher.Encrypt(crypt[i:i+keySize], data[i:i+keySize])
	}
	return crypt, nil
}
