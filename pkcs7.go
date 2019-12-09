package main

// PadPKCS7 pads a given byte slice to be a multiple
// of blockSize using the PKCS7 standard (RFC2315)
func PadPKCS7(data []byte, blockSize int) []byte {
	out := make([]byte, len(data))
	copy(out, data)

	// work out how much we need to pad
	padNum := blockSize - len(data)%blockSize

	// In PKCS7, the pad value is = to the number of bytes to pad
	for i := 0; i < padNum; i++ {
		out = append(out, byte(padNum))
	}
	return out
}
