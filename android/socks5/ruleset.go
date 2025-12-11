package socks5

import (
	"fmt"
	"io"
)

type PermitCommand struct {
	CmdConnect bool
	CmdBind    bool
	CmdUdp     bool
}

const (
	ConnectCommand   = uint8(0x01)
	BindCommand      = uint8(0x02)
	AssociateCommand = uint8(0x03)
)

type RuleSet interface {
	Allow(write io.Writer, buf []byte) error
}

func PermitAll() RuleSet {
	return &PermitCommand{
		CmdConnect: true,
		CmdBind:    true,
		CmdUdp:     true,
	}
}

func PermitNone() RuleSet {
	return &PermitCommand{
		CmdConnect: false,
		CmdBind:    false,
		CmdUdp:     false,
	}
}

func (p *PermitCommand) Allow(write io.Writer, buf []byte) error {
	cmd := buf[1]
	if cmd == ConnectCommand && !p.CmdConnect {
		write.Write([]byte{Version, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("CONNECT command not allowed")
	}
	if cmd == BindCommand && !p.CmdBind {
		write.Write([]byte{Version, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("BIND command not allowed")
	}
	if cmd == AssociateCommand && !p.CmdUdp {
		write.Write([]byte{Version, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("UDP command not allowed")
	}

	return nil
}
