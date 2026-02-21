package main

import (
	"fmt"
	"log"

	"github.com/Kes0x6f/Log-Based--IDS/internal/filehandler"
	"github.com/Kes0x6f/Log-Based--IDS/internal/parser"
)

func main() {
	file, err := filehandler.OpenFile("logs/sample_auth.log")

	if err != nil {
		log.Fatal(err)
	}
	events := parser.AuthLogParser(file)

	for _, e := range events {
		fmt.Println(*e)
	}
}
