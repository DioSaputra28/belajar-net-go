package test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/DioSaputra28/belajar-net-go/android/socks5"
)

func TestServerNoAuth(t *testing.T) {
	l, err := net.Listen("tcp", ":1080")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Errorf("err: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Errorf("err: %v", err)
			return
		}

		if !bytes.Equal(buf, []byte("ping")) {
			t.Errorf("bad: %v", buf)
			return
		}
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	config := &socks5.Config{
		AuthMethods: []socks5.Authenticator{
			&socks5.NoAuthAuthenticator{},
		},
	}

	server, err := socks5.New(config)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", ":1081")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	defer listener.Close()

	fmt.Println("SOCKS5 server (NoAuth) started on :1081")

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("Failed to accept connection: %v", err)
			return
		}

		if err := server.ServeConn(conn); err != nil {
			t.Errorf("Connection error: %v", err)
		}
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := net.Dial("tcp", ":1081")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	greeting := []byte{5, 1, socks5.NoAuth}
	if _, err := conn.Write(greeting); err != nil {
		t.Fatalf("Failed to send greeting: %v", err)
	}

	authResp := make([]byte, 2)
	if _, err := io.ReadAtLeast(conn, authResp, 2); err != nil {
		t.Fatalf("Failed to read auth response: %v", err)
	}

	if authResp[0] != socks5.Version || authResp[1] != socks5.NoAuth {
		t.Fatalf("Unexpected auth response: %v (expected [5 0])", authResp)
	}

	req := bytes.NewBuffer(nil)
	req.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})
	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	req.Write(port)

	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatalf("Failed to send CONNECT request: %v", err)
	}

	connectResp := make([]byte, 10)
	if _, err := io.ReadAtLeast(conn, connectResp, 10); err != nil {
		t.Fatalf("Failed to read CONNECT response: %v", err)
	}

	if connectResp[0] != 5 || connectResp[1] != 0 {
		t.Fatalf("CONNECT failed: %v", connectResp)
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Failed to send ping: %v", err)
	}

	pong := make([]byte, 4)
	if _, err := io.ReadAtLeast(conn, pong, 4); err != nil {
		t.Fatalf("Failed to read pong: %v", err)
	}

	if !bytes.Equal(pong, []byte("pong")) {
		t.Fatalf("Expected 'pong', got: %v", pong)
	}

	fmt.Println("Test passed! SOCKS5 proxy is working correctly.")
}

func TestServerUserPassAuth(t *testing.T) {
	// Create target server (ping/pong)
	l, err := net.Listen("tcp", ":1084")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Errorf("err: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Errorf("err: %v", err)
			return
		}

		if !bytes.Equal(buf, []byte("ping")) {
			t.Errorf("bad: %v", buf)
			return
		}
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Create SOCKS5 server with UserPass auth
	creds := socks5.StaticCredentials{
		"testuser": "testpass",
	}

	config := &socks5.Config{
		AuthMethods: []socks5.Authenticator{
			&socks5.UserPassAuthenticator{Credentials: creds},
		},
	}

	server, err := socks5.New(config)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", ":1082")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer listener.Close()

	fmt.Println("SOCKS5 server (UserPass) started on :1082")

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("Failed to accept connection: %v", err)
			return
		}

		if err := server.ServeConn(conn); err != nil {
			t.Errorf("Connection error: %v", err)
		}
	}()

	time.Sleep(10 * time.Millisecond)

	// Client connects
	conn, err := net.Dial("tcp", ":1082")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Step 1: Send greeting with UserPassAuth
	greeting := []byte{5, 1, socks5.UserPassAuth}
	if _, err := conn.Write(greeting); err != nil {
		t.Fatalf("Failed to send greeting: %v", err)
	}

	authResp := make([]byte, 2)
	if _, err := io.ReadAtLeast(conn, authResp, 2); err != nil {
		t.Fatalf("Failed to read auth response: %v", err)
	}

	if authResp[0] != socks5.Version || authResp[1] != socks5.UserPassAuth {
		t.Fatalf("Unexpected auth response: %v (expected [5 2])", authResp)
	}

	// Step 2: Send username/password
	authReq := bytes.NewBuffer(nil)
	authReq.Write([]byte{1})          // Auth version
	authReq.Write([]byte{8})          // Username length
	authReq.Write([]byte("testuser")) // Username
	authReq.Write([]byte{8})          // Password length
	authReq.Write([]byte("testpass")) // Password

	if _, err := conn.Write(authReq.Bytes()); err != nil {
		t.Fatalf("Failed to send auth credentials: %v", err)
	}

	authResult := make([]byte, 2)
	if _, err := io.ReadAtLeast(conn, authResult, 2); err != nil {
		t.Fatalf("Failed to read auth result: %v", err)
	}

	if authResult[0] != 1 || authResult[1] != socks5.AuthSuccess {
		t.Fatalf("Auth failed: %v (expected [1 0])", authResult)
	}

	// Step 3: Send CONNECT request
	req := bytes.NewBuffer(nil)
	req.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})
	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	req.Write(port)

	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatalf("Failed to send CONNECT request: %v", err)
	}

	connectResp := make([]byte, 10)
	if _, err := io.ReadAtLeast(conn, connectResp, 10); err != nil {
		t.Fatalf("Failed to read CONNECT response: %v", err)
	}

	if connectResp[0] != 5 || connectResp[1] != 0 {
		t.Fatalf("CONNECT failed: %v", connectResp)
	}

	// Step 4: Send/receive data through proxy
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Failed to send ping: %v", err)
	}

	pong := make([]byte, 4)
	if _, err := io.ReadAtLeast(conn, pong, 4); err != nil {
		t.Fatalf("Failed to read pong: %v", err)
	}

	if !bytes.Equal(pong, []byte("pong")) {
		t.Fatalf("Expected 'pong', got: %v", pong)
	}

	fmt.Println("Test passed! UserPass authentication is working correctly.")
}

func TestServerInvalidCredentials(t *testing.T) {
	creds := socks5.StaticCredentials{
		"validuser": "validpass",
	}

	config := &socks5.Config{
		AuthMethods: []socks5.Authenticator{
			&socks5.UserPassAuthenticator{Credentials: creds},
		},
	}

	server, err := socks5.New(config)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", ":1083")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer listener.Close()

	fmt.Println("SOCKS5 server (Invalid Creds Test) started on :1083")

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("Failed to accept connection: %v", err)
			return
		}

		if err := server.ServeConn(conn); err == nil {
			t.Errorf("Expected auth error, but got nil")
		}
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := net.Dial("tcp", ":1083")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send greeting
	greeting := []byte{5, 1, socks5.UserPassAuth}
	if _, err := conn.Write(greeting); err != nil {
		t.Fatalf("Failed to send greeting: %v", err)
	}

	authResp := make([]byte, 2)
	if _, err := io.ReadAtLeast(conn, authResp, 2); err != nil {
		t.Fatalf("Failed to read auth response: %v", err)
	}

	// Send WRONG credentials
	authReq := bytes.NewBuffer(nil)
	authReq.Write([]byte{1})           // Auth version
	authReq.Write([]byte{8})           // Username length
	authReq.Write([]byte("wrongusr"))  // Wrong username
	authReq.Write([]byte{9})           // Password length
	authReq.Write([]byte("wrongpass")) // Wrong password

	if _, err := conn.Write(authReq.Bytes()); err != nil {
		t.Fatalf("Failed to send auth credentials: %v", err)
	}

	authResult := make([]byte, 2)
	if _, err := io.ReadAtLeast(conn, authResult, 2); err != nil {
		t.Fatalf("Failed to read auth result: %v", err)
	}

	// Should get auth failure
	if authResult[0] != 1 || authResult[1] != socks5.AuthFailure {
		t.Fatalf("Expected auth failure [1 1], got: %v", authResult)
	}

	fmt.Println("Test passed! Invalid credentials are correctly rejected.")
}

func TestRulesetPermissions(t *testing.T) {
	t.Run("PermitAll", func(t *testing.T) {
		permit := socks5.PermitAll().(*socks5.PermitCommand)

		// Test CONNECT allowed
		buf := []byte{5, socks5.ConnectCommand, 0, 1}
		err := permit.Allow(io.Discard, buf)
		if err != nil {
			t.Errorf("CONNECT should be allowed: %v", err)
		}

		// Test BIND allowed
		buf = []byte{5, socks5.BindCommand, 0, 1}
		err = permit.Allow(io.Discard, buf)
		if err != nil {
			t.Errorf("BIND should be allowed: %v", err)
		}

		// Test UDP allowed
		buf = []byte{5, socks5.AssociateCommand, 0, 1}
		err = permit.Allow(io.Discard, buf)
		if err != nil {
			t.Errorf("UDP should be allowed: %v", err)
		}
	})

	t.Run("PermitNone", func(t *testing.T) {
		permit := socks5.PermitNone().(*socks5.PermitCommand)

		// Test CONNECT denied
		buf := []byte{5, socks5.ConnectCommand, 0, 1}
		err := permit.Allow(io.Discard, buf)
		if err == nil {
			t.Error("CONNECT should be denied")
		}

		// Test BIND denied
		buf = []byte{5, socks5.BindCommand, 0, 1}
		err = permit.Allow(io.Discard, buf)
		if err == nil {
			t.Error("BIND should be denied")
		}

		// Test UDP denied
		buf = []byte{5, socks5.AssociateCommand, 0, 1}
		err = permit.Allow(io.Discard, buf)
		if err == nil {
			t.Error("UDP should be denied")
		}
	})

	t.Run("CustomPermit", func(t *testing.T) {
		// Only allow CONNECT
		permit := &socks5.PermitCommand{
			CmdConnect: true,
			CmdBind:    false,
			CmdUdp:     false,
		}

		// Test CONNECT allowed
		buf := []byte{5, socks5.ConnectCommand, 0, 1}
		err := permit.Allow(io.Discard, buf)
		if err != nil {
			t.Errorf("CONNECT should be allowed: %v", err)
		}

		// Test BIND denied
		buf = []byte{5, socks5.BindCommand, 0, 1}
		err = permit.Allow(io.Discard, buf)
		if err == nil {
			t.Error("BIND should be denied")
		}

		// Test UDP denied
		buf = []byte{5, socks5.AssociateCommand, 0, 1}
		err = permit.Allow(io.Discard, buf)
		if err == nil {
			t.Error("UDP should be denied")
		}
	})

	fmt.Println("Test passed! Ruleset permissions are working correctly.")
}
