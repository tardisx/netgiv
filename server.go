package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

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

	conn.SetDeadline(time.Now().Add(time.Second))

	sharedKey := secure.Handshake(conn)
	secureConnection := secure.SecureConnection{Conn: conn, SharedKey: sharedKey, Buffer: &bytes.Buffer{}}

	gob.Register(secure.PacketStart{})
	gob.Register(secure.PacketSendDataStart{})

	dec := gob.NewDecoder(&secureConnection)

	// At this point we are in
	for {

		p1 := secure.PacketStart{}

		log.Print("trying to decode something from wire")
		err := dec.Decode(&p1)
		if err == io.EOF {
			log.Printf("connection has been closed")
			return
		}
		if err != nil {
			panic(err)
		}

		log.Printf("Decoded packet:\n%#v", p1)

		p2 := secure.PacketSendDataStart{}

		err = dec.Decode(&p2)
		if err == io.EOF {
			log.Printf("connection has been closed")
			return
		}
		if err != nil {
			panic(err)
		}

		log.Printf("Decoded packet:\n%#v", p2)

	}
}
