package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/jwillberg/spf"
)

func main() {
	debug := flag.Bool("debug", false, "Enable debug output")
	flag.Parse()

	if *debug {
		spf.EnableDebug()
	}

	args := flag.Args()
	if len(args) != 2 {
		fmt.Println("Usage: go run main.go [--debug] <ip> <domain>")
		os.Exit(1)
	}

	ip := args[0]
	domain := args[1]

	result, err := spf.SPFCheck(ip, domain)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	fmt.Printf("SPF check result for IP %s sending from domain %s: %s\n", ip, domain, result)
}
