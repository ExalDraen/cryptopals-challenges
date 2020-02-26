package main

import (
	"log"
	"testing"
)

func TestKVParse(t *testing.T) {
	ex := []struct {
		inp string
		exp map[string]string
	}{
		{"foo=bar", map[string]string{"foo": "bar"}},
		{"email=foo@bar.com&uid=10&role=user", map[string]string{"email": "foo@bar.com", "uid": "10", "role": "user"}},
	}

	for _, e := range ex {
		kv, err := KvParse(e.inp)
		if err != nil {
			log.Fatalf("failed to parse kv %v: %v", e.inp, err)
		}

		if !compare(e.exp, kv) {
			t.Errorf("KV parse of %v failed: \nExp: %v \nGot: %v", e.inp, e.exp, kv)
		}
	}
}

func compare(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
