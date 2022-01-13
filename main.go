package main

import (
	"flag"
	"fmt"
	"log"
)

func main() {
	log.SetFlags(log.Lshortfile)
	port := flag.Int("p", 9000, "Port to run server/client on.")
	addr := flag.String("a", "61.245.149.58", "address to connect to.")
	isServer := flag.Bool("s", false, "Set if running the server.")
	flag.Parse()

	if *isServer {
		fmt.Printf("Server running on %d\n", *port)
		s := Server{port: *port}
		s.Run()
	} else {
		fmt.Printf("Client running on %d\n", *port)
		c := Client{port: *port, address: *addr}
		err := c.Connect()
		if err != nil {
			fmt.Print(err)
		}
	}
}
