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

	"github.com/h2non/filetype"

	"github.com/tardisx/netgiv/secure"
)

type Server struct {
	port int
}

// An NGF is a Netgiv File
type NGF struct {
	StorePath string
	Filename  string // could be empty string if we were not supplied with one
	Kind      string //
	Size      uint64 // file size
}

func (s *Server) Run() {
	address := fmt.Sprintf(":%d", s.port)
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

	conn.SetDeadline(time.Now().Add(time.Second * 5))

	sharedKey := secure.Handshake(conn)
	secureConnection := secure.SecureConnection{Conn: conn, SharedKey: sharedKey, Buffer: &bytes.Buffer{}}

	gob.Register(secure.PacketStart{})
	gob.Register(secure.PacketSendDataStart{})

	dec := gob.NewDecoder(&secureConnection)

	// Get the start packet
	start := secure.PacketStart{}

	err := dec.Decode(&start)
	if err == io.EOF {
		log.Printf("connection has been closed after start packet")
		return
	}
	if err != nil {
		log.Printf("some error with start packet: %w", err)
		return
	}

	log.Printf("Decoded packet:\n%#v", start)
	conn.SetDeadline(time.Now().Add(time.Second * 5))

	if start.OperationType == secure.OperationTypeSend {
		log.Printf("client wants to send us something, expecting a send start")
		sendStart := secure.PacketSendDataStart{}

		err = dec.Decode(&sendStart)
		if err != nil {
			log.Printf("error at send data start: %w", err)
			return
		}
		log.Printf("send start looks like: %v", sendStart)
		file, err := os.CreateTemp("", "netgiv_")
		defer file.Close()

		ngf := NGF{
			StorePath: file.Name(),
			Filename:  sendStart.Filename,
			Kind:      "",
			Size:      0,
		}

		if err != nil {
			log.Printf("got error with temp file: %w", err)
			return
		}
		log.Printf("writing data to file: %s", file.Name())
		sendData := secure.PacketSendDataNext{}
		determinedKind := false
		for {
			conn.SetDeadline(time.Now().Add(time.Second * 5))
			err = dec.Decode(&sendData)
			if err == io.EOF {
				log.Printf("WE ARE DONE writing to: %s", file.Name())
				break
			}
			if err != nil {
				log.Printf("error decoding data next: %s", err)
				return
			}

			// filetype.Match needs a few hundred bytes - I guess there is a chance
			// we don't have enough in the very first packet? This might need rework.
			if !determinedKind {
				kind, _ := filetype.Match(sendData.Data)
				ngf.Kind = kind.MIME.Value
				determinedKind = true
			}

			file.Write(sendData.Data)
		}
		info, err := file.Stat()
		if err != nil {
			log.Printf("couldn't stat file %s", err)
			return
		}
		ngf.Size = uint64(info.Size())
		log.Printf("received a %#v", ngf)
		file.Close()

		return
	} else {
		log.Printf("bad operation")
		return
	}

}
