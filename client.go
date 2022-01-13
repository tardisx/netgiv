package main

import (
	"bufio"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/tardisx/netgiv/secure"
)

type Client struct {
	address string
	port    int
}

func (c *Client) Connect() error {
	address := fmt.Sprintf("%s:%d", c.address, c.port)

	serverAddress, _ := net.ResolveTCPAddr("tcp", address)

	conn, err := net.DialTCP("tcp", nil, serverAddress)
	if err != nil {
		return errors.New("problem connecting to server, is it running?\n")
	}
	defer conn.Close()

	fmt.Printf("Connection on %s\n", address)

	sharedKey := secure.Handshake(conn)
	secureConnection := secure.SecureConnection{Conn: conn, SharedKey: sharedKey}

	// reader := bufio.NewReader(os.Stdin)
	enc := gob.NewEncoder(&secureConnection)

	for {

		msg := secure.PacketStart{
			OperationType:   secure.OperationTypeSend,
			ClientName:      "Justin Hawkins",
			ProtocolVersion: "v1.0",
			AuthToken:       "abc123",
		}

		// gob.Register(secure.PacketSendStart{})
		err := enc.Encode(msg)
		if err != nil {
			panic(err)
		}

		data := secure.PacketSendDataStart{
			Filename:  "foobar",
			TotalSize: 3,
		}
		err = enc.Encode(data)
		if err != nil {
			panic(err)
		}
		log.Print("done that")

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
			// process buf

			send := secure.PacketSendDataNext{
				Size: 5000,
				Data: buf,
			}
			enc.Encode(send)
			// time.Sleep(time.Second)
			if err != nil {
				log.Fatal(err)
			}
		}
		log.Println("Bytes:", nBytes, "Chunks:", nChunks)

		conn.Close()

		break
		// response := make([]byte, 1024)

		// _, err = secureConnection.Read(response)
		// if err != nil {
		// 	fmt.Print("Connection to the server was closed.\n")
		// 	break
		// }

		// fmt.Printf("%s\n", response)
	}

	return nil
}
