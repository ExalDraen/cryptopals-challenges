package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

// C8 implements the solutions to set 1 challenge 8
func C8() {
	fmt.Println("---------------------- c8 ------------------------")
	var bestScore int
	var bestRes []byte

	file, err := os.Open("set1c8data.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		txt, err := hex.DecodeString(scanner.Text())
		if err != nil {
			log.Fatal("Failed to decode hex string, exiting")
		}
		if s := ScoreECB(txt); s > bestScore {
			bestScore = s
			bestRes = txt
			fmt.Printf("New likely ECB with score %v: %x\n", s, txt)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Best score %v for: %x\n", bestScore, bestRes)
}
