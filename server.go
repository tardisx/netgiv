package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/h2non/filetype"

	"github.com/tardisx/netgiv/secure"
)

type Server struct {
	port int
}

// An NGF is a Netgiv File
type NGF struct {
	Id        uint32
	StorePath string
	Filename  string // could be empty string if we were not supplied with one
	Kind      string //
	Size      uint64 // file size
	Timestamp time.Time
}

var ngfs []NGF
var globalId uint32

func (s *Server) Run() {
	address := fmt.Sprintf(":%d", s.port)
	networkAddress, _ := net.ResolveTCPAddr("tcp", address)

	listener, err := net.ListenTCP("tcp", networkAddress)
	if err != nil {
		fmt.Print(err)
		os.Exit(2)
	}

	ngfs = make([]NGF, 0)

	go func() {
		sigchan := make(chan os.Signal)
		signal.Notify(sigchan, os.Interrupt)
		<-sigchan

		for _, ngf := range ngfs {
			log.Printf("removing file: %s", ngf.StorePath)
			err := os.Remove(ngf.StorePath)
			if err != nil {
				log.Printf("could not remove %s: %v", ngf.StorePath, err)
			}
		}
		os.Exit(0)
	}()

	// start main program tasks

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
	enc := gob.NewEncoder(&secureConnection)

	// Get the start packet
	start := secure.PacketStart{}

	err := dec.Decode(&start)
	if err == io.EOF {
		log.Printf("connection has been closed prematurely")
		return
	}
	if err != nil {
		log.Printf("error while expecting PacketStart: %v", err)
		return
	}

	conn.SetDeadline(time.Now().Add(time.Second * 5))

	if start.OperationType == secure.OperationTypeSend {
		log.Printf("file incoming")

		sendStart := secure.PacketSendDataStart{}

		err = dec.Decode(&sendStart)
		if err != nil {
			log.Printf("error - expecting PacketSendDataStart: %v", err)
			return
		}
		file, err := os.CreateTemp("", "netgiv_")
		if err != nil {
			log.Fatalf("can't open tempfile: %v", err)
		}
		defer file.Close()

		ngf := NGF{
			StorePath: file.Name(),
			Filename:  sendStart.Filename,
			Kind:      "",
			Size:      0,
			Id:        atomic.AddUint32(&globalId, 1),
			Timestamp: time.Now(),
		}

		if err != nil {
			log.Printf("got error with temp file: %w", err)
			return
		}
		sendData := secure.PacketSendDataNext{}
		determinedKind := false
		for {
			conn.SetDeadline(time.Now().Add(time.Second * 5))
			err = dec.Decode(&sendData)
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Printf("error while expecting PacketSendDataNext: %s", err)
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
		file.Close()

		ngfs = append(ngfs, ngf)
		log.Printf("done receiving file")

		return
	} else if start.OperationType == secure.OperationTypeReceive {
		log.Printf("client requesting file receive")
		// wait for them to send the request
		req := secure.PacketReceiveDataStartRequest{}
		err := dec.Decode(&req)
		if err != nil {
			log.Printf("error expecting PacketReceiveDataStartRequest: %v", err)
			return
		}

		log.Printf("The asked for %v", req)

		// do we have this ngf by id?
		var requestedNGF *NGF

		if len(ngfs) > 0 {
			if req.Id == 0 {
				// they want the most recent one
				requestedNGF = &ngfs[len(ngfs)-1]
			} else {
				for _, ngf := range ngfs {
					if ngf.Id == req.Id {
						requestedNGF = &ngf
					}
				}
			}
		}

		if requestedNGF == nil {
			// not found
			log.Printf("user requested %d, not found", req.Id)
			res := secure.PacketReceiveDataStartResponse{
				Status: secure.ReceiveDataStartResponseNotFound,
			}
			err = enc.Encode(res)
			if err != nil {
				log.Printf("could not send NotFound: %v", err)
			}

			return
		}

		res := secure.PacketReceiveDataStartResponse{
			Status:    secure.ReceiveDataStartResponseOK,
			Filename:  requestedNGF.Filename,
			Kind:      requestedNGF.Kind,
			TotalSize: uint32(requestedNGF.Size),
		}
		err = enc.Encode(res)
		if err != nil {
			log.Printf("error sending PacketReceiveDataStartResponse: %v", err)
			return
		}
		// now just start sending the file in batches
		buf := make([]byte, 2048)
		filename := requestedNGF.StorePath
		log.Printf("opening %s", filename)
		f, err := os.Open(filename)
		if err != nil {
			log.Printf("could not find file %s: %v", filename, err)
			return
		}

		for {
			n, err := f.Read(buf)
			eof := false

			if err != nil && err != io.EOF {
				log.Printf("error reading data: %v", err)
				break
			}
			if err == io.EOF {
				eof = true
			}

			chunk := secure.PacketReceiveDataNext{
				Size: uint16(n),
				Data: buf[:n],
				Last: eof,
			}
			err = enc.Encode(chunk)
			if err != nil {
				log.Printf("error sending chunk: %v", err)
			}

			if eof {
				break
			}
		}
		log.Printf("sending done")
		return

	} else if start.OperationType == secure.OperationTypeList {
		log.Printf("client requesting file list")

		for _, ngf := range ngfs {
			p := secure.PacketListData{}
			p.FileSize = uint32(ngf.Size)
			p.Kind = ngf.Kind
			p.Id = ngf.Id
			p.Filename = ngf.Filename
			enc.Encode(p)
		}
		log.Printf("done sending list, closing connection")

		return

	} else {
		log.Printf("bad operation")
		return
	}

}
