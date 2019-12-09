package main

import (
	"crypto/aes"
	"fmt"
)

// AesDecrypt decrypts a given set of data that was encrypted
// with AES in ECB.
// The original data is not modified.
func AesDecrypt(data, key []byte) ([]byte, error) {
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
