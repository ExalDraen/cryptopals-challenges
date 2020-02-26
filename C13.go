package main

import (
	"fmt"
	"strconv"
	"strings"
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
