package pals

import (
	"bytes"
	"testing"
)

func TestPKCS7Pad(t *testing.T) {
	ex := []struct {
		n        int
		input    []byte
		expected []byte
	}{
		{8, []byte(""), []byte("\x08\x08\x08\x08\x08\x08\x08\x08")},
		{8, []byte("a"), []byte("a\x07\x07\x07\x07\x07\x07\x07")},
		{8, []byte("ab"), []byte("ab\x06\x06\x06\x06\x06\x06")},
		{8, []byte("abc"), []byte("abc\x05\x05\x05\x05\x05")},
		{8, []byte("abcd"), []byte("abcd\x04\x04\x04\x04")},
		{8, []byte("abcde"), []byte("abcde\x03\x03\x03")},
		{8, []byte("abcdef"), []byte("abcdef\x02\x02")},
		{8, []byte("abcdefg"), []byte("abcdefg\x01")},
		{8, []byte("abcdefgh"), []byte("abcdefgh\x08\x08\x08\x08\x08\x08\x08\x08")},
		{8, []byte("abcdefgh1"), []byte("abcdefgh1\x07\x07\x07\x07\x07\x07\x07")},
		{16, []byte(""), []byte("\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")},
		{16, []byte("a"), []byte("a\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f")},
		{20, []byte("YELLOW SUBMARINE"), []byte("YELLOW SUBMARINE\x04\x04\x04\x04")},
	}
	for _, e := range ex {
		result := PadPKCS7(e.input, e.n)
		if !bytes.Equal(result, e.expected) {
			t.Errorf("Pad failed: Expected: %v Got: %v", e.expected, result)
		}
	}
}
