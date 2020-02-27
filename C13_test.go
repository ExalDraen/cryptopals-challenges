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

func TestKVEncode(t *testing.T) {
	ex := []struct {
		inp User
		exp string
	}{
		{User{email: "foo@bar.com", uid: 10, role: "user"}, "email=foo@bar.com&uid=10&role=user"},
		{User{email: "foo@bar.com&role=admin", uid: 10, role: "user"}, "email=foo@bar.comroleadmin&uid=10&role=user"},
	}

	for _, e := range ex {
		enc := e.inp.KvEncode()

		if e.exp != enc {
			t.Errorf("KV Encode of %v failed: \nExp: %v \nGot: %v", e.inp, e.exp, enc)
		}
	}
}

func TestEncryptDecryptCycle(t *testing.T) {
	ex := []struct {
		u User
		k []byte
	}{
		{User{email: "foo@bar.com", uid: 10, role: "user"}, []byte("Please test me!!")},
		{User{email: "quu@fux.floo", uid: 0, role: "admin"}, []byte("Please test me!!")},
		{User{email: "quu@fux.floo", uid: 0, role: "admin"}, []byte("YELLOW SUBMARINE")},
	}

	for _, e := range ex {
		crypt := e.u.Encrypt(e.k)
		decrypt, err := DecryptUser(crypt, e.k)
		if err != nil {
			log.Fatalf("failed to decrypt kv %v: %v", crypt, err)
		}

		if !compare(e.u, decrypt) {
			t.Errorf("Encrypt-Decrypt with key %v failed: \nExp: %v \nGot: %v", e.k, e.u, decrypt)
		}
	}
}

func compare(a, b User) bool {
	return a.email == b.email && a.uid == b.uid && a.role == b.role
}
