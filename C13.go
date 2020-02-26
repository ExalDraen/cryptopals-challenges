package main

import (
	"fmt"
	"strings"
)

// C13 solution
func C13() {
	fmt.Println("---------------------- c13 ------------------------")

}

// KvParse parses the a string of k=v pairs concatenated
// with '&', e.g. foo=bar&baz=qux&zap=zazzle
func KvParse(input string) (map[string]string, error) {
	v := make(map[string]string)

	pairs := strings.Split(input, "&")
	for _, p := range pairs {
		if strings.Count(p, "=") != 1 {
			return nil, fmt.Errorf("Malformed kv pair %v ", p)
		}
		kv := strings.Split(p, "=")
		v[kv[0]] = kv[1]
	}

	return v, nil
}
