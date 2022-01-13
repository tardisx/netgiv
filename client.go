package main

import (
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/tardisx/netgiv/secure"
)

type Client struct {
	port int
}

func (c *Client) Connect() error {
	address := fmt.Sprintf("127.0.0.1:%d", c.port)
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
			Data:      []byte{0x20, 0x21, 0x22},
		}
		err = enc.Encode(data)
		if err != nil {
			panic(err)
		}
		log.Print("done that")
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
