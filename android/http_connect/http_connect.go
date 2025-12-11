package httpconnect

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

type Config struct {
	Credential CredentialStore
	Auth       Authenticator
}

func Server(config *Config) {
	if config == nil {
		config = &Config{
			Auth: &NoAuthAuthenticator{},
		}
	}
	if config.Auth == nil {
		config.Auth = &NoAuthAuthenticator{}
	}

	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal("Failed to listen: ", err)
	}
	defer listener.Close()

	fmt.Println("HTTP CONNECT server started on :8080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn, config)
	}
}

func requiresAuth(auth Authenticator) bool {
	_, isNoAuth := auth.(*NoAuthAuthenticator)
	return !isNoAuth
}

func handleConnection(conn net.Conn, config *Config) {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	firstLine, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Failed to read first line: %v", err)
		return
	}

	fmt.Println("First line:", firstLine)

	parts := strings.Split(strings.TrimSpace(firstLine), " ")
	if len(parts) != 3 || parts[0] != "CONNECT" {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	target := parts[1]
	fmt.Println("Target:", target)

	var authHeader string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimSpace(line)

		if line == "" {
			break
		}

		if strings.HasPrefix(line, "Proxy-Authorization:") {
			authHeader = strings.TrimPrefix(line, "Proxy-Authorization:")
			authHeader = strings.TrimSpace(authHeader)
		}
	}

	if requiresAuth(config.Auth) {
		if authHeader == "" {
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n"))
			conn.Write([]byte("Proxy-Authenticate: Basic realm=\"Proxy\"\r\n"))
			conn.Write([]byte("\r\n"))
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Basic" {
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}

		token := parts[1]

		if err := config.Auth.Authenticate(token, config.Credential); err != nil {
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return
		}
	}

	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go io.Copy(targetConn, conn)
	io.Copy(conn, targetConn)
}
