package pals

const keySize = 16

// RandomKey is a key that is randomly generated at package initialization
// time and stays constant during a program's execution
var RandomKey []byte

func init() {
	var err error
	RandomKey, err = GenerateRandomBytes(keySize)
	if err != nil {
		panic(err)
	}
}
