package socks5

import (
	"fmt"
	"io"
)

const (
	NoAuth       = uint8(0)
	UserPassAuth = uint8(2)
	NoAcceptable = uint8(255)
	AuthSuccess  = uint8(0)
	AuthFailure  = uint8(1)

	UserAuthVersion = uint8(1)
)

var (
	UserAuthFailed  = fmt.Errorf("user authentication failed")
	NoSupportedAuth = fmt.Errorf("no supported authentication")
)

type Authenticator interface {
	Authenticate(reader io.Reader, writer io.Writer) error
	GetCode() uint8
}

type NoAuthAuthenticator struct{}

func (n *NoAuthAuthenticator) GetCode() uint8 {
	return NoAuth
}

func (n *NoAuthAuthenticator) Authenticate(reader io.Reader, writer io.Writer) error {
	_, err := writer.Write([]byte{Version, NoAuth})
	return err
}

type UserPassAuthenticator struct {
	Credentials CredentialStore
}

func (u *UserPassAuthenticator) GetCode() uint8 {
	return UserPassAuth
}

func (u *UserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer) error {
	_, err := writer.Write([]byte{Version, UserPassAuth})
	if err != nil {
		return err
	}

	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(reader, header, 2); err != nil {
		return err
	}

	if header[0] != UserAuthVersion {
		return fmt.Errorf("Unsupported auth version: %v", header[0])
	}

	usernameLen := int(header[1])
	username := make([]byte, usernameLen)
	if _, err := io.ReadAtLeast(reader, username, usernameLen); err != nil {
		return err
	}

	if _, err := io.ReadAtLeast(reader, header[:1], 1); err != nil {
		return err
	}

	passwordLen := int(header[0])
	password := make([]byte, passwordLen)
	if _, err := io.ReadAtLeast(reader, password, passwordLen); err != nil {
		return err
	}

	if u.Credentials.Valid(string(username), string(password)) {
		_, err := writer.Write([]byte{UserAuthVersion, AuthSuccess})
		return err
	}

	writer.Write([]byte{UserAuthVersion, AuthFailure})
	return UserAuthFailed
}

func noAcceptableAuth(conn io.Writer) error {
	conn.Write([]byte{Version, NoAcceptable})
	return NoSupportedAuth
}
