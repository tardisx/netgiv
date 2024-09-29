package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"time"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"

	"github.com/h2non/filetype"

	"github.com/tardisx/netgiv/secure"
)

type Server struct {
	port      int
	authToken string
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

func (ngf NGF) String() string {
	return fmt.Sprintf("id: %d, stored: %s, size: %d, kind: %s", ngf.Id, ngf.StorePath, ngf.Size, ngf.Kind)
}

var ngfs []NGF
var globalId uint32

func (s *Server) Run() {
	log.Info(versionInfo(false))
	log.Infof("starting server on :%d", s.port)
	address := fmt.Sprintf(":%d", s.port)
	networkAddress, _ := net.ResolveTCPAddr("tcp", address)

	listener, err := net.ListenTCP("tcp", networkAddress)
	if err != nil {
		log.Fatalf("error creating listener: %v", err)
	}

	ngfs = make([]NGF, 0)

	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, os.Interrupt)
		<-sigchan

		for _, ngf := range ngfs {
			log.Printf("removing file: %s", ngf.StorePath)
			err := os.Remove(ngf.StorePath)
			if err != nil {
				log.Errorf("could not remove %s: %v", ngf.StorePath, err)
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

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn *net.TCPConn) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(time.Second * 5))

	sharedKey := secure.Handshake(conn)
	secureConnection := secure.SecureConnection{Conn: conn, SharedKey: sharedKey, Buffer: &bytes.Buffer{}}

	gob.Register(secure.PacketStartRequest{})
	gob.Register(secure.PacketSendDataStart{})

	dec := gob.NewDecoder(&secureConnection)
	enc := gob.NewEncoder(&secureConnection)

	// Get the start packet
	start := secure.PacketStartRequest{}

	err := dec.Decode(&start)
	if err == io.EOF {
		log.Errorf("connection has been closed prematurely")
		return
	}

	if err != nil {
		log.Errorf("error while expecting PacketStart: %v", err)
		return
	}

	// tell the client if the connection is ok.
	startResponse := secure.PacketStartResponse{}

	if start.ProtocolVersion != ProtocolVersion {
		log.Errorf("bad protocol version")
		startResponse.Response = secure.PacketStartResponseEnumWrongProtocol
		_ = enc.Encode(startResponse)
		return
	}

	if start.AuthToken != s.authToken {
		log.Errorf("bad authtoken")
		startResponse.Response = secure.PacketStartResponseEnumBadAuthToken
		_ = enc.Encode(startResponse)
		return
	}

	// otherwise we are good to continue, tell the client that
	startResponse.Response = secure.PacketStartResponseEnumOK
	_ = enc.Encode(startResponse)

	_ = conn.SetDeadline(time.Now().Add(time.Second * 5))

	switch start.OperationType {
	case secure.OperationTypeSend:
		log.Debugf("file incoming")

		sendStart := secure.PacketSendDataStart{}

		err = dec.Decode(&sendStart)
		if err != nil {
			log.Errorf("error - expecting PacketSendDataStart: %v", err)
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
			log.Errorf("got error with temp file: %v", err)
			return
		}
		sendData := secure.PacketSendDataNext{}
		determinedKind := false
		for {
			_ = conn.SetDeadline(time.Now().Add(time.Second * 5))
			err = dec.Decode(&sendData)
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Errorf("error while expecting PacketSendDataNext: %s", err)
				return
			}

			// filetype.Match needs a few hundred bytes - I guess there is a chance
			// we don't have enough in the very first packet? This might need rework.
			if !determinedKind {
				kind, _ := filetype.Match(sendData.Data)

				if kind.MIME.Value == "" {
					// this is pretty fragile. If our chunk boundary happens in the
					// middle of an actual UTF-8 character, we will fail this test.
					// However it's good for small chunks of text which fit in a
					// single chunk, which I suspect to be a common use case.
					if utf8.ValidString(string(sendData.Data)) {
						ngf.Kind = "UTF-8 text"
					}
				} else {
					ngf.Kind = kind.MIME.Value
				}

				determinedKind = true
			}

			_, _ = file.Write(sendData.Data)
		}
		info, err := file.Stat()
		if err != nil {
			log.Errorf("couldn't stat file %s", err)
			return
		}
		ngf.Size = uint64(info.Size())
		file.Close()

		ngfs = append(ngfs, ngf)
		log.Printf("done receiving file: %v", ngf)

		return
	case secure.OperationTypeReceive:
		log.Printf("client requesting file receive")
		// wait for them to send the request
		req := secure.PacketReceiveDataStartRequest{}
		err := dec.Decode(&req)
		if err != nil {
			log.Errorf("error expecting PacketReceiveDataStartRequest: %v", err)
			return
		}

		log.Debugf("The asked for %v", req)

		// do we have this ngf by id?
		var requestedNGF NGF

		if len(ngfs) > 0 {
			if req.Id == 0 {
				// they want the most recent one
				requestedNGF = ngfs[len(ngfs)-1]
			} else {
				for _, ngf := range ngfs {
					if ngf.Id == req.Id {
						requestedNGF = ngf
					}
				}
			}
		}

		log.Debugf("going to deliver %v", requestedNGF)

		if requestedNGF.Id == 0 {
			// not found
			log.Errorf("user requested %d, not found", req.Id)
			res := secure.PacketReceiveDataStartResponse{
				Status: secure.ReceiveDataStartResponseNotFound,
			}
			err = enc.Encode(res)
			if err != nil {
				log.Errorf("could not send NotFound: %v", err)
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
			log.Errorf("error sending PacketReceiveDataStartResponse: %v", err)
			return
		}
		// now just start sending the file in batches
		buf := make([]byte, 2048)
		filename := requestedNGF.StorePath
		log.Debugf("opening %s", filename)
		f, err := os.Open(filename)
		if err != nil {
			log.Errorf("could not find file %s: %v", filename, err)
			return
		}

		for {
			n, err := f.Read(buf)
			eof := false

			if err != nil && err != io.EOF {
				log.Errorf("error reading data: %v", err)
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
				log.Errorf("error sending chunk: %v", err)
			}

			if eof {
				break
			}
		}
		log.Printf("sending done")
		return
	case secure.OperationTypeList:
		log.Debugf("client requesting file list")

		for _, ngf := range ngfs {
			p := secure.PacketListData{}
			p.FileSize = uint32(ngf.Size)
			p.Kind = ngf.Kind
			p.Id = ngf.Id
			p.Filename = ngf.Filename
			p.Timestamp = ngf.Timestamp
			_ = enc.Encode(p)
		}
		log.Debugf("done sending list, closing connection")

		return
	case secure.OperationTypeBurn:
		log.Debugf("client requesting burn")
		// wait for them to send the request
		req := secure.PacketBurnRequest{}
		err := dec.Decode(&req)
		if err != nil {
			log.Errorf("error expecting PacketBurnRequest: %v", err)
			return
		}

		log.Debugf("The client asked for %v to be burned", req)

		// do we have this ngf by id?
		var requestedNGF NGF

		if len(ngfs) > 0 {
			if req.Id == 0 {
				// they want the most recent one
				requestedNGF = ngfs[len(ngfs)-1]
			} else {
				for _, ngf := range ngfs {
					if ngf.Id == req.Id {
						requestedNGF = ngf
					}
				}
			}
		}

		log.Debugf("going to burn %v", requestedNGF)

		if requestedNGF.Id == 0 {
			// not found
			log.Errorf("user requested burning %d, not found", req.Id)
			res := secure.PacketBurnResponse{
				Status: secure.BurnResponseNotFound,
			}
			err = enc.Encode(res)
			if err != nil {
				log.Errorf("could not send NotFound: %v", err)
			}

			return
		}

		// remove the file
		err = os.Remove(requestedNGF.StorePath)
		if err != nil {
			log.Errorf("could not remove file %s: %v", requestedNGF.StorePath, err)
			return
		}

		// remove the ngf from the list
		for i, ngf := range ngfs {
			if ngf.Id == requestedNGF.Id {
				ngfs = append(ngfs[:i], ngfs[i+1:]...)
				break
			}
		}

		res := secure.PacketBurnResponse{
			Status: secure.BurnResponseOK,
		}
		err = enc.Encode(res)
		if err != nil {
			log.Errorf("error sending PacketBurnResponse: %v", err)
			return
		}

		log.Printf("burn complete")
		return
	default:
		log.Errorf("bad operation")
		return
	}
}
