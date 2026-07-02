package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

var variant = "dev"

func main() {
	credPath := flag.String("cred", "", "path to credential file")
	connectAddr := flag.String("connect", "", "TCP address to connect to")
	holdSecs := flag.Int("hold", 8, "seconds to hold resources open")
	flag.Parse()

	var credFile *os.File
	var conn net.Conn

	// Open credential file if specified
	if *credPath != "" {
		var err error
		credFile, err = os.Open(*credPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error opening credential file: %v\n", err)
			os.Exit(1)
		}
		// Read up to 256 bytes but keep handle open
		buf := make([]byte, 256)
		credFile.Read(buf)
	}

	// Establish TCP connection if specified
	if *connectAddr != "" {
		var err error
		conn, err = net.Dial("tcp", *connectAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error connecting to %s: %v\n", *connectAddr, err)
			os.Exit(1)
		}
		// Write one byte
		conn.Write([]byte{0})
	}

	// Signal readiness
	fmt.Printf("ready variant=%s pid=%d\n", variant, os.Getpid())
	os.Stdout.Sync()

	// Hold resources open for specified duration
	time.Sleep(time.Duration(*holdSecs) * time.Second)

	// Close resources
	if credFile != nil {
		credFile.Close()
	}
	if conn != nil {
		conn.Close()
	}
}
