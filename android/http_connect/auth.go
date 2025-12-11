package httpconnect

import (
	"encoding/base64"
	"fmt"
	"strings"
)

type Authenticator interface {
	Authenticate(token string, credential CredentialStore) error
}

type NoAuthAuthenticator struct{}

func (n *NoAuthAuthenticator) Authenticate(token string, credential CredentialStore) error {
	return nil
}

type UserPassAuthenticator struct{}

func (u *UserPassAuthenticator) Authenticate(token string, credential CredentialStore) error {
	decodeToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return err
	}

	credentials := string(decodeToken)

	creds := strings.SplitN(credentials, ":", 2)
	if len(creds) != 2 {
		return fmt.Errorf("invalid credentials format")
	}

	username := creds[0]
	password := creds[1]

	if !credential.Valid(username, password) {
		return fmt.Errorf("invalid credentials")
	}

	return nil
}
