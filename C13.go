package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ExalDraen/cryptopals-challenges/pals"
)

// User represents as user as per C13's definition
type User struct {
	email string
	uid   int
	role  string
}

// KvEncode does the revers of KvParse - takes a map and turns
// it into an encoded string
// & in strings are stripped
func (u *User) KvEncode() string {
	return fmt.Sprintf("email=%v&uid=%v&role=%v", sanitize(u.email), u.uid, sanitize(u.role))
}

// Encrypt returns the encrypted version of the encoded user profile,
// padded if necessary
func (u *User) Encrypt(key []byte) []byte {
	padded := pals.PadPKCS7([]byte(u.KvEncode()), len(key))
	crypt, err := pals.AesEncryptECB(padded, key)
	if err != nil {
		panic(err)
	}
	return crypt
}

// C13 solution
func C13() {
	fmt.Println("---------------------- c13 ------------------------")

}

// ProfileFor generates an encoded representation of a user profile
// for the given email
func ProfileFor(email string) string {
	u := User{
		email: email,
		uid:   10,
		role:  "user",
	}
	return u.KvEncode()
}

// DecryptUser decrypts the given encrypted user profile
// and parses it into a user, which is returned
func DecryptUser(data, key []byte) (User, error) {
	enc, err := pals.AesDecryptECB(data, key)
	if err != nil {
		return User{}, fmt.Errorf("failed to decrypt data with key %v: %v", key, err)
	}

	u, err := KvParse(string(pals.UnpadPKCS7(enc)))
	if err != nil {
		return User{}, fmt.Errorf("failed to parse user profile %v: %v", enc, err)
	}
	return u, nil
}

// KvParse parses a kv string into a user
func KvParse(input string) (User, error) {
	v := make(map[string]string)

	pairs := strings.Split(input, "&")
	for _, p := range pairs {
		if strings.Count(p, "=") != 1 {
			return User{}, fmt.Errorf("Malformed kv pair %v ", p)
		}
		kv := strings.Split(p, "=")
		v[kv[0]] = kv[1]
	}

	uid, err := strconv.Atoi(v["uid"])
	if err != nil {
		return User{}, fmt.Errorf("Malformed uid pair %v ", v["uid"])
	}

	u := User{
		email: v["email"],
		role:  v["role"],
		uid:   uid,
	}

	return u, nil
}

// strips illegal metacharacters
func sanitize(s string) string {
	return strings.Replace(strings.Replace(s, "&", "", -1), "=", "", -1)
}
