package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/mattn/go-isatty"
)

func main() {
	log.SetFlags(log.Lshortfile)
	port := flag.Int("port", 9000, "Port to run server/client on.")
	addr := flag.String("a", "127.0.0.1", "address to connect to.")
	isServer := flag.Bool("s", false, "Set if running the server.")
	isList := flag.Bool("l", false, "Set if requesting a list")
	isSend := flag.Bool("c", false, "Set if sending a file (copy)")
	isReceive := flag.Bool("p", false, "Set if receiving a file (paste)")

	flag.Parse()

	if *isServer {
		log.Printf("Server running on %d\n", *port)
		s := Server{port: *port}
		s.Run()
	} else {
		if !*isList && !*isSend && !*isReceive {
			// try to work out the intent based on whether or not stdin/stdout
			// are ttys
			stdinTTY := isatty.IsTerminal(os.Stdin.Fd())
			stdoutTTY := isatty.IsTerminal(os.Stdout.Fd())

			if stdinTTY && !stdoutTTY {
				*isReceive = true

			} else if !stdinTTY && stdoutTTY {
				*isSend = true
			}

		}

		if !*isList && !*isSend && !*isReceive {
			// could default to list?
			*isList = true
		}

		c := Client{port: *port, address: *addr, list: *isList, send: *isSend, receive: *isReceive}
		err := c.Connect()
		if err != nil {
			fmt.Print(err)
		}
	}
}
