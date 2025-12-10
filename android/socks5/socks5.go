package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	Version = 5
)

type Server struct {
	config      *Config
	authMethods map[uint8]Authenticator
}

type Config struct {
	AuthMethods []Authenticator
	Credential  CredentialStore
}

func New(conf *Config) (*Server, error) {
	if len(conf.AuthMethods) == 0 {
		if conf.Credential != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthenticator{Credentials: conf.Credential}}
		} else {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	server := &Server{
		config: conf,
	}

	server.authMethods = make(map[uint8]Authenticator)
	for _, a := range conf.AuthMethods {
		server.authMethods[a.GetCode()] = a
	}

	return server, nil
}

func (s *Server) ServeConn(conn net.Conn) error {
	defer conn.Close()

	if err := s.authenticate(conn); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	return s.handleRequest(conn)
}

func (s *Server) authenticate(conn net.Conn) error {
	buff := make([]byte, 257)

	n, err := conn.Read(buff)
	if err != nil || n < 2 {
		return fmt.Errorf("failed to read greeting: %w", err)
	}

	if buff[0] != Version {
		return fmt.Errorf("unsupported SOCKS version: %d", buff[0])
	}
	nmethods := int(buff[1])
	if n < 2+nmethods {
		return fmt.Errorf("incomplete greeting")
	}

	methods := buff[2 : 2+nmethods]

	for _, method := range methods {
		if auth, found := s.authMethods[method]; found {
			return auth.Authenticate(conn, conn)
		}
	}

	return noAcceptableAuth(conn)
}

func (s *Server) handleRequest(conn net.Conn) error {
	buff := make([]byte, 512)
	n, err := conn.Read(buff)
	if err != nil || n < 4 {
		return fmt.Errorf("failed to read request: %w", err)
	}

	if buff[0] != Version {
		return fmt.Errorf("unsupported SOCKS version: %d", buff[0])
	}

	cmd := buff[1]
	if cmd != 0x01 {
		conn.Write([]byte{Version, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("unsupported command: %d", cmd)
	}

	atyp := buff[3]
	var host string
	var port int
	i := 4

	switch atyp {
	case 0x01: // IPv4
		if n < i+4+2 {
			return fmt.Errorf("incomplete IPv4 address")
		}
		host = net.IP(buff[i : i+4]).String()
		i += 4
	case 0x03: // Domain
		dlen := int(buff[i])
		i++
		if n < i+dlen+2 {
			return fmt.Errorf("incomplete domain name")
		}
		host = string(buff[i : i+dlen])
		i += dlen
	case 0x04: // IPv6
		if n < i+16+2 {
			return fmt.Errorf("incomplete IPv6 address")
		}
		host = net.IP(buff[i : i+16]).String()
		i += 16
	default:
		conn.Write([]byte{Version, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("unsupported address type: %d", atyp)
	}

	port = int(binary.BigEndian.Uint16(buff[i : i+2]))
	target := net.JoinHostPort(host, strconv.Itoa(port))

	fmt.Printf("[PROXY] %s -> %s:%d\n", conn.RemoteAddr(), host, port)

	dst, err := net.Dial("tcp", target)
	if err != nil {
		conn.Write([]byte{Version, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("failed to connect to target: %w", err)
	}
	defer dst.Close()

	conn.Write([]byte{Version, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(dst, conn)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(conn, dst)
		errCh <- err
	}()

	<-errCh
	return nil
}
