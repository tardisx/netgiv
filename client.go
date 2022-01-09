package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"

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
		return errors.New("Problem connecting to server, is it running?\n")
	}
	defer conn.Close()

	fmt.Printf("Connection on %s\n", address)

	sharedKey := secure.Handshake(conn)
	secureConnection := secure.SecureConnection{Conn: conn, SharedKey: sharedKey}

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("> ")
		// Read up to the newline character
		msg, _ := reader.ReadBytes(0xA)
		// Kill the newline char
		msg = msg[:len(msg)-1]

		_, err := secureConnection.Write(msg)

		response := make([]byte, 1024)

		_, err = secureConnection.Read(response)
		if err != nil {
			fmt.Print("Connection to the server was closed.\n")
			break
		}

		fmt.Printf("%s\n", response)
	}

	return nil
}
