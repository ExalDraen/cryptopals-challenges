package pals

import "bytes"

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

// UnpadPKCS7 removes PKCS7 padding from the given byte slice
// at the given block size (RFC2315)
// the original data is unmodified
func UnpadPKCS7(data []byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)

	// PKCS7 always produces even-sized blocks
	if len(data)%2 == 1 {
		return data
	}

	// PKCS7 padding values are >0 and < length of the data
	lastByte := data[len(data)-1]
	padLen := int(lastByte)
	if lastByte == 0 || padLen > len(data) {
		return data
	}

	// PKCS7 padding values are == number of padding bytes
	testPad := bytes.Repeat([]byte{lastByte}, padLen)

	if bytes.Equal(testPad, data[len(data)-padLen:]) {
		return out[:len(out)-padLen]
	}

	// if we get here the data wasn't padded, so return it unchanged
	return out
}
