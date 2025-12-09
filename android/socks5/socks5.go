package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

type Socks5 struct {
}

func (s *Socks5) HandleConnection(conn net.Conn) {
	defer conn.Close() 

	buff := make([]byte, 512) 
	n, err := conn.Read(buff)
	if err != nil || n < 2 {
		return
	}

	if buff[0] != 0x05 {
		return
	}
	conn.Write([]byte{5, 0})


	n, err = conn.Read(buff)
	if err != nil || n < 4 {
		return
	}

	if buff[0] != 0x05 {
		return
	}

	cmd := buff[1]
	if cmd != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) 
		return
	}

	atyp := buff[3]

	var host string
	var port int

	i := 4

	if atyp == 0x01 {
		if n < i+4+2 {
			return
		}
		host = net.IP(buff[i : i+4]).String()
		i += 4
	} else if atyp == 0x03 { 
		dlen := int(buff[i])
		fmt.Println(dlen)
		i++
		if n < i+dlen+2 {
			return
		}
		host = string(buff[i : i+dlen])
		i += dlen
	} else if atyp == 0x04 { 
		if n < i+16+2 {
			return
		}
		host = net.IP(buff[i : i+16]).String()
		i += 16
	} else {
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) 
		return
	}

	port = int(binary.BigEndian.Uint16(buff[i : i+2]))
	target := net.JoinHostPort(host, stringPort(port))

	dst, err := net.Dial("tcp", target)
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) 
		return
	}
	defer dst.Close()

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	go io.Copy(dst, conn)
	io.Copy(conn, dst)
}

func stringPort(p int) string {
	return strconv.Itoa(p)
}
