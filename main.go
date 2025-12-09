package main

import (
	"fmt"
	"net"

	"github.com/DioSaputra28/belajar-net-go/android/socks5"
)

func main() {
	l, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}
	fmt.Println("Socks5 server started on :8080")
	server := socks5.Socks5{}
	for {
		conn, err := l.Accept()
		if err != nil {
			panic(err)
		}
		go server.HandleConnection(conn)
	}
}
