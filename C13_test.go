package main

import (
	"log"
	"testing"
)

func TestKVParse(t *testing.T) {
	ex := []struct {
		inp string
		exp User
	}{
		{"email=foo@bar.com&uid=10&role=user", User{email: "foo@bar.com", uid: 10, role: "user"}},
		{"email=quu@fux.floo&uid=0&role=admin", User{email: "quu@fux.floo", uid: 0, role: "admin"}},
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

func compare(a, b User) bool {
	return a.email == b.email && a.uid == b.uid && a.role == b.role
}
