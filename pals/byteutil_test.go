package pals

import (
	"bytes"
	"testing"
)

func TestByteChunking(t *testing.T) {
	ex := []struct {
		n        int
		input    []byte
		expected [][]byte
	}{
		{2, []byte("\x01\x02\x03\x04"), [][]byte{[]byte("\x01\x02"), []byte("\x03\x04")}},
		{3, []byte("\x01\x02\x03\x04\x05\x06"), [][]byte{[]byte("\x01\x02\x03"), []byte("\x04\x05\x06")}},
		{2, []byte("\x08\x08"), [][]byte{[]byte("\x08\x08")}},
		{2, []byte("\x01\x02\x03"), [][]byte{[]byte("\x01\x02")}},
		{3, []byte("\x01\x02"), [][]byte{}},
		{2, []byte(""), [][]byte{}},
	}

	for _, e := range ex {
		result := ChunkBytes(e.input, e.n)
		if !blocksEqual(result, e.expected) {
			t.Errorf("Chunking %v failed: Expected: %v Got: %v", e.input, e.expected, result)
		}
	}
}

func TestByteUnchunking(t *testing.T) {
	ex := []struct {
		input    [][]byte
		expected []byte
	}{
		{[][]byte{[]byte("\x01\x02"), []byte("\x03\x04")}, []byte("\x01\x02\x03\x04")},
		{[][]byte{[]byte("\x01\x02\x03"), []byte("\x04\x05\x06")}, []byte("\x01\x02\x03\x04\x05\x06")},
	}

	for _, e := range ex {
		result := UnchunkBytes(e.input)
		if !bytes.Equal(result, e.expected) {
			t.Errorf("Unchunking %v failed: Expected: %v Got: %v", e.input, e.expected, result)
		}
	}
}

func blocksEqual(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if !bytes.Equal(left[i], right[i]) {
			return false
		}
	}
	return true
}
