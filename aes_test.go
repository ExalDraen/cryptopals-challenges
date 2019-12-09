package main

import (
	"testing"
)

func TestAesECBCycle(t *testing.T) {
	ex := []struct {
		plain string
		key   string
	}{
		{"YELLOW SUBMARINEYELLOW SUBMARINE", "YELLOW SUBMARINE"},
	}
	for _, e := range ex {
		encrypted, err := AesEncryptECB([]byte(e.plain), []byte(e.key))
		if err != nil {
			t.Error("Failed to encrypt")
		}
		decrypted, _ := AesDecryptECB(encrypted, []byte(e.key))
		if err != nil {
			t.Error("Failed to decrypt")
		}

		if string(decrypted) != e.plain {
			t.Errorf("Failed to encrypt-decrypt: Plain: %v, Key: %v, Encrypted: %v, Decrypted: %v", e.plain, e.key, encrypted, decrypted)
		}
	}
}
