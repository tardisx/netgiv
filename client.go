package main

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/dustin/go-humanize"
	"github.com/tardisx/netgiv/secure"
)

type Client struct {
	address    string
	port       int
	list       bool
	send       bool
	receiveNum int
	authToken  string
}

func (c *Client) Connect() error {
	address := fmt.Sprintf("%s:%d", c.address, c.port)

	d := net.Dialer{Timeout: 5 * time.Second}

	conn, err := d.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("problem connecting to server, is it running?: %v", err)
	}
	defer conn.Close()

	log.Debugf("established connection on %s", address)

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		log.Fatal("could not assert")
	}

	sharedKey := secure.Handshake(tcpConn)
	secureConnection := secure.SecureConnection{Conn: conn, SharedKey: sharedKey, Buffer: &bytes.Buffer{}}

	enc := gob.NewEncoder(&secureConnection)
	dec := gob.NewDecoder(&secureConnection)

	if c.list {
		log.Debugf("requesting file list")

		err := c.connectToServer(secure.OperationTypeList, enc, dec)
		if err != nil {
			return fmt.Errorf("could not connect and auth: %v", err)
		}

		// now we expect to get stuff back until we don't
		for {
			listPacket := secure.PacketListData{}
			err := dec.Decode(&listPacket)
			if err == io.EOF {
				break
			}
			if err != nil {
				panic(err)
			}
			fmt.Printf("%d: %s (%s)\n", listPacket.Id, listPacket.Kind, humanize.Bytes(uint64(listPacket.FileSize)))
		}
		conn.Close()
		log.Debugf("done listing")

	} else if c.receiveNum >= 0 {
		log.Debugf("receiving file %d", c.receiveNum)

		err := c.connectToServer(secure.OperationTypeReceive, enc, dec)
		if err != nil {
			return fmt.Errorf("could not connect and auth: %v", err)
		}

		req := secure.PacketReceiveDataStartRequest{
			Id: uint32(c.receiveNum),
		}
		err = enc.Encode(req)
		if err != nil {
			panic(err)
		}
		// expect a response telling us if we can go ahead
		res := secure.PacketReceiveDataStartResponse{}
		err = dec.Decode(&res)
		if err != nil {
			panic(err)
		}

		if res.Status == secure.ReceiveDataStartResponseOK {
			for {
				res := secure.PacketReceiveDataNext{}
				err = dec.Decode(&res)
				if err != nil {
					panic(err)
				}
				os.Stdout.Write(res.Data[:res.Size])
				if res.Last {
					break
				}
			}
			log.Debugf("finished")
		} else if res.Status == secure.ReceiveDataStartResponseNotFound {
			log.Error("ngf not found")
		} else {
			panic("unknown status")
		}

		conn.Close()
	} else if c.send {
		//  send mode

		err := c.connectToServer(secure.OperationTypeSend, enc, dec)
		if err != nil {
			return fmt.Errorf("could not connect and auth: %v", err)
		}

		data := secure.PacketSendDataStart{
			Filename:  "",
			TotalSize: 0,
		}
		err = enc.Encode(data)
		if err != nil {
			panic(err)
		}

		nBytes, nChunks := int64(0), int64(0)
		reader := bufio.NewReader(os.Stdin)
		buf := make([]byte, 0, 1024)

		for {
			n, err := reader.Read(buf[:cap(buf)])

			buf = buf[:n]

			if n == 0 {
				if err == nil {
					continue
				}
				if err == io.EOF {
					break
				}
				log.Fatal(err)
			}
			nChunks++
			nBytes += int64(len(buf))

			send := secure.PacketSendDataNext{
				Size: 5000,
				Data: buf,
			}
			err = enc.Encode(send)
			// time.Sleep(time.Second)
			if err != nil {
				log.Fatal(err)
			}
		}
		log.Debugf("Sent %s in %d chunks", humanize.Bytes(uint64(nBytes)), nChunks)

		conn.Close()

	} else {
		panic("no client mode set")
	}
	return nil

}

func (c *Client) connectToServer(op secure.OperationTypeEnum, enc *gob.Encoder, dec *gob.Decoder) error {

	// list mode
	startPacket := secure.PacketStartRequest{
		OperationType:   op,
		ClientName:      "",
		ProtocolVersion: "1.0",
		AuthToken:       c.authToken,
	}
	err := enc.Encode(startPacket)
	if err != nil {
		return fmt.Errorf("could not send start packet: %v", err)
	}

	// check the response is ok
	response := secure.PacketStartResponse{}
	err = dec.Decode(&response)
	if err != nil {
		return fmt.Errorf("could not receive start packet response: %v", err)
	}

	if response.Response == secure.PacketStartResponseEnumWrongProtocol {
		log.Print("wrong protocol version")
		return errors.New("protocol version mismatch")

	}
	if response.Response == secure.PacketStartResponseEnumBadAuthToken {
		log.Print("bad authtoken")
		return errors.New("bad authtoken")
	}
	return nil
}
