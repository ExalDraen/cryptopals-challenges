package main

import "fmt"

// Set2 solutions
func Set2() {
	//Challenge 1
	C1S2()
}

// C1S2 solutions
func C1S2() {
	fmt.Println("---------------------- c1 ------------------------")
	const trial = "YELLOW SUBMARINE"
	fmt.Printf("Trial %v padded to 20: %q", trial, string(PadPKCS7([]byte(trial), 20)))
}
