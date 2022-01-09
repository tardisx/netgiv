package main

import (
	"fmt"
	"net"
	"os"

	"github.com/tardisx/netgiv/secure"
)

type Server struct {
	port int
}

func (s *Server) Run() {
	address := fmt.Sprintf("127.0.0.1:%d", s.port)
	networkAddress, _ := net.ResolveTCPAddr("tcp", address)

	listener, err := net.ListenTCP("tcp", networkAddress)
	if err != nil {
		fmt.Print(err)
		os.Exit(2)
	}

	for {
		conn, err := listener.AcceptTCP()

		if err != nil {
			fmt.Print(err)
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn *net.TCPConn) {
	defer conn.Close()
	sharedKey := secure.Handshake(conn)
	secureConnection := secure.SecureConnection{Conn: conn, SharedKey: sharedKey}

	for {
		msg := make([]byte, 1024)
		_, err := secureConnection.Read(msg)

		if err != nil {
			break
		}

		secureConnection.Write(msg)
	}
}
