package main

import (
	"fmt"
	"log"
	"net"

	"github.com/DioSaputra28/belajar-net-go/android/socks5"
)

func main() {
	runNoAuthServer()

	// runUserPassServer()
}

func runNoAuthServer() {
	config := &socks5.Config{
		AuthMethods: []socks5.Authenticator{
			&socks5.NoAuthAuthenticator{},
		},
	}

	server, err := socks5.New(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	fmt.Println("SOCKS5 server (NoAuth) started on :8080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go func() {
			if err := server.ServeConn(conn); err != nil {
				log.Printf("Connection error: %v", err)
			}
		}()
	}
}

func runUserPassServer() {
	credentials := socks5.StaticCredentials{
		"alice": "password123",
		"bob":   "secret456",
	}

	config := &socks5.Config{
		AuthMethods: []socks5.Authenticator{
			&socks5.UserPassAuthenticator{
				Credentials: credentials,
			},
		},
	}

	server, err := socks5.New(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	fmt.Println("🔐 SOCKS5 server (UserPass) started on :8080")
	fmt.Println("Valid credentials:")
	fmt.Println("  - alice:password123")
	fmt.Println("  - bob:secret456")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go func() {
			if err := server.ServeConn(conn); err != nil {
				log.Printf("Connection error: %v", err)
			}
		}()
	}
}
