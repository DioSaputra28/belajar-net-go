package test

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	httpconnect "github.com/DioSaputra28/belajar-net-go/android/http_connect"
)

func TestHTTPConnectNoAuth(t *testing.T) {
	// Create target server (echo server)
	targetListener, err := net.Listen("tcp", ":9001")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()

	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		io.ReadFull(conn, buf)
		if string(buf) == "ping" {
			conn.Write([]byte("pong"))
		}
	}()

	// Start HTTP CONNECT proxy with NoAuth
	config := &httpconnect.Config{
		Auth: &httpconnect.NoAuthAuthenticator{},
	}

	proxyListener, err := net.Listen("tcp", ":8081")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer proxyListener.Close()

	go func() {
		for {
			conn, err := proxyListener.Accept()
			if err != nil {
				return
			}
			go handleProxyConnection(conn, config)
		}
	}()

	time.Sleep(10 * time.Millisecond)

	// Client connects to proxy
	conn, err := net.Dial("tcp", ":8081")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send CONNECT request WITHOUT auth
	connectReq := "CONNECT localhost:9001 HTTP/1.1\r\n"
	connectReq += "Host: localhost:9001\r\n"
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("Failed to send CONNECT: %v", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read status: %v", err)
	}

	if !strings.Contains(statusLine, "200 Connection Established") {
		t.Fatalf("Expected 200, got: %s", statusLine)
	}

	// Skip remaining headers
	for {
		line, _ := reader.ReadString('\n')
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// Send data through tunnel
	conn.Write([]byte("ping"))

	pong := make([]byte, 4)
	if _, err := io.ReadFull(conn, pong); err != nil {
		t.Fatalf("Failed to read pong: %v", err)
	}

	if string(pong) != "pong" {
		t.Fatalf("Expected 'pong', got: %s", pong)
	}

	fmt.Println("Test passed! NoAuth HTTP CONNECT is working.")
}

func TestHTTPConnectWithAuth(t *testing.T) {
	// Create target server
	targetListener, err := net.Listen("tcp", ":9002")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()

	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		io.ReadFull(conn, buf)
		if string(buf) == "ping" {
			conn.Write([]byte("pong"))
		}
	}()

	// Start HTTP CONNECT proxy with UserPass auth
	creds := httpconnect.StaticCredentials{
		"testuser": "testpass",
	}

	config := &httpconnect.Config{
		Credential: creds,
		Auth:       &httpconnect.UserPassAuthenticator{},
	}

	proxyListener, err := net.Listen("tcp", ":8082")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer proxyListener.Close()

	go func() {
		for {
			conn, err := proxyListener.Accept()
			if err != nil {
				return
			}
			go handleProxyConnection(conn, config)
		}
	}()

	time.Sleep(10 * time.Millisecond)

	// Client connects with valid credentials
	conn, err := net.Dial("tcp", ":8082")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Encode credentials
	auth := base64.StdEncoding.EncodeToString([]byte("testuser:testpass"))

	// Send CONNECT request WITH auth
	connectReq := "CONNECT localhost:9002 HTTP/1.1\r\n"
	connectReq += "Host: localhost:9002\r\n"
	connectReq += "Proxy-Authorization: Basic " + auth + "\r\n"
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("Failed to send CONNECT: %v", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read status: %v", err)
	}

	if !strings.Contains(statusLine, "200 Connection Established") {
		t.Fatalf("Expected 200, got: %s", statusLine)
	}

	// Skip headers
	for {
		line, _ := reader.ReadString('\n')
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// Test tunnel
	conn.Write([]byte("ping"))

	pong := make([]byte, 4)
	if _, err := io.ReadFull(conn, pong); err != nil {
		t.Fatalf("Failed to read pong: %v", err)
	}

	if string(pong) != "pong" {
		t.Fatalf("Expected 'pong', got: %s", pong)
	}

	fmt.Println("Test passed! UserPass authentication is working.")
}

func TestHTTPConnectInvalidAuth(t *testing.T) {
	creds := httpconnect.StaticCredentials{
		"validuser": "validpass",
	}

	config := &httpconnect.Config{
		Credential: creds,
		Auth:       &httpconnect.UserPassAuthenticator{},
	}

	proxyListener, err := net.Listen("tcp", ":8083")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer proxyListener.Close()

	go func() {
		for {
			conn, err := proxyListener.Accept()
			if err != nil {
				return
			}
			go handleProxyConnection(conn, config)
		}
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := net.Dial("tcp", ":8083")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send WRONG credentials
	auth := base64.StdEncoding.EncodeToString([]byte("wronguser:wrongpass"))

	connectReq := "CONNECT localhost:9999 HTTP/1.1\r\n"
	connectReq += "Proxy-Authorization: Basic " + auth + "\r\n"
	connectReq += "\r\n"

	conn.Write([]byte(connectReq))

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read status: %v", err)
	}

	if !strings.Contains(statusLine, "403 Forbidden") {
		t.Fatalf("Expected 403, got: %s", statusLine)
	}

	fmt.Println("Test passed! Invalid credentials are rejected.")
}

func TestHTTPConnectMissingAuth(t *testing.T) {
	creds := httpconnect.StaticCredentials{
		"user": "pass",
	}

	config := &httpconnect.Config{
		Credential: creds,
		Auth:       &httpconnect.UserPassAuthenticator{},
	}

	proxyListener, err := net.Listen("tcp", ":8084")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer proxyListener.Close()

	go func() {
		for {
			conn, err := proxyListener.Accept()
			if err != nil {
				return
			}
			go handleProxyConnection(conn, config)
		}
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := net.Dial("tcp", ":8084")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send CONNECT without auth header
	connectReq := "CONNECT localhost:9999 HTTP/1.1\r\n"
	connectReq += "\r\n"

	conn.Write([]byte(connectReq))

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read status: %v", err)
	}

	if !strings.Contains(statusLine, "407 Proxy Authentication Required") {
		t.Fatalf("Expected 407, got: %s", statusLine)
	}

	// Check for Proxy-Authenticate header
	foundProxyAuth := false
	for {
		line, _ := reader.ReadString('\n')
		if strings.TrimSpace(line) == "" {
			break
		}
		if strings.Contains(line, "Proxy-Authenticate") {
			foundProxyAuth = true
		}
	}

	if !foundProxyAuth {
		t.Fatal("Missing Proxy-Authenticate header in 407 response")
	}

	fmt.Println("Test passed! Missing auth returns 407 with proper headers.")
}

func TestHTTPConnectBadRequest(t *testing.T) {
	config := &httpconnect.Config{
		Auth: &httpconnect.NoAuthAuthenticator{},
	}

	proxyListener, err := net.Listen("tcp", ":8085")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer proxyListener.Close()

	go func() {
		for {
			conn, err := proxyListener.Accept()
			if err != nil {
				return
			}
			go handleProxyConnection(conn, config)
		}
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := net.Dial("tcp", ":8085")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send invalid request (GET instead of CONNECT)
	badReq := "GET / HTTP/1.1\r\n\r\n"
	conn.Write([]byte(badReq))

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read status: %v", err)
	}

	if !strings.Contains(statusLine, "400 Bad Request") {
		t.Fatalf("Expected 400, got: %s", statusLine)
	}

	fmt.Println("Test passed! Bad requests are rejected.")
}

// Helper function to handle proxy connections (mimics the actual server logic)
func handleProxyConnection(conn net.Conn, config *httpconnect.Config) {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read CONNECT request
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Split(strings.TrimSpace(firstLine), " ")
	if len(parts) != 3 || parts[0] != "CONNECT" {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	target := parts[1]

	// Read headers
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

	// Check auth
	_, isNoAuth := config.Auth.(*httpconnect.NoAuthAuthenticator)
	if !isNoAuth {
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

		if err := config.Auth.Authenticate(parts[1], config.Credential); err != nil {
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return
		}
	}

	// Connect to target
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
