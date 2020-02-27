package main

import (
	"bytes"
	"fmt"
	"log"
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
	adminProfile := genAdminProfile()
	fmt.Printf("Generated admin profile cyphertext: %v\n", adminProfile)
	adminUser, err := DecryptUser(adminProfile, pals.RandomKey)
	if err != nil {
		log.Fatalf("failed to decrypt generated admin profile: %v", err)
	}
	fmt.Printf("Admin user decrypts to %+v: \n", adminUser)
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

// EncryptedProfileFor generates an encrypted representation of a user profile
// for the given email
func EncryptedProfileFor(email string) []byte {
	u := User{
		email: email,
		uid:   10,
		role:  "user",
	}
	return u.Encrypt(pals.RandomKey)
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

// discoverProfileBlockSize finds the size of the cypher blocks
// used to encrypt user profiles
// Do this by repeatedly increasing the input until the return size changes
func discoverProfileBlockSize() (int, error) {
	var initLen, nextLen int // lengths of crypt text
	const maxSize = 2048
	var inp []byte

	initLen = len(EncryptedProfileFor(""))
	for i := 1; i <= maxSize; i++ {
		inp = bytes.Repeat([]byte("A"), i)
		nextLen = len(EncryptedProfileFor(string(inp)))
		if nextLen > initLen {
			return nextLen - initLen, nil
		}
	}
	return 0, fmt.Errorf("unable to find block size, went to max: %v", maxSize)
}

// genAdminProfile creates a valid cyphertext whose payload will
// decrypt into a user with admin role.
func genAdminProfile() []byte {
	// generate a role=admin profile by repeated calls to ProfileFor
	// Goal is to stitch the following blocks
	// (1) |email=...&uid=10&role=| where ... is chosen by us
	// (2) |adminPPPPPPPPP|  where P is padding
	// Combining these: |email=...&uid=10&role=|adminPPPPPPPPPP|
	// which would decrypt to
	// email=...&uid=10&role=admin

	// To get block (1), choose ... such that the last block contains "user", the bit we don't want
	// to do that, we need email=...&uid=10&role=) to fully fill one or more blocks.
	//
	// Then grab the first encrypted block
	// To get block (2), we want to construct a situation where
	/// |email=..............|adminPPPPPPPPPP|&uid=10&role=user|

	// Get (1)
	blockSize, err := discoverProfileBlockSize()
	if err != nil {
		log.Fatalf("couldn't discover block size: %v", err)
	}
	fmt.Printf("Found profile block size: %v\n", blockSize)
	// Generate appropriately sized email to "user" in the final block:
	// We don't bother generating a working email address here :)
	nBlocks := len("email=&uid=10&role=")/blockSize + 1
	email := strings.Repeat("A", nBlocks*blockSize-len("email=&uid=10&role="))
	crypt := EncryptedProfileFor(email)
	cryptTrimmed := crypt[:len(crypt)-blockSize]

	// Get (2)
	email = strings.Repeat("A", blockSize-len("email="))
	email = email + string(pals.PadPKCS7([]byte("admin"), blockSize))
	secondBlock := EncryptedProfileFor(email)[blockSize : blockSize*2]

	return append(cryptTrimmed, secondBlock...)
}
