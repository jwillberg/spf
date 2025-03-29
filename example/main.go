package main

import (
	"flag"
	"fmt"
	"os"
	"time"


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

	start := time.Now() // ⏱️ Start timer
	// With Memcached
	result, err := spf.SPFCheck(ip, domain, "127.0.0.1:11211")
	// Without Memcached
	//result, err := spf.SPFCheck(ip, domain, "")
	elapsed := time.Since(start) // ⏱️ Stop time

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	fmt.Printf("SPF check result for IP %s sending from domain %s: %s (in %s)\n", ip, domain, result, elapsed)
}
