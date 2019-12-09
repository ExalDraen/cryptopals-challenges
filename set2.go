package main

import "fmt"

// Set2 solutions
func Set2() {
	//Challenge 1
	C9()
}

// C9 solutions
func C9() {
	fmt.Println("---------------------- c1 ------------------------")
	const trial = "YELLOW SUBMARINE"
	fmt.Printf("Trial %v padded to 20: %q\n", trial, string(PadPKCS7([]byte(trial), 20)))
}
