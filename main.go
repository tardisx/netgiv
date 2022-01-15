package main

import (
	"flag"
	"fmt"
	"log"
)

func main() {
	log.SetFlags(log.Lshortfile)
	port := flag.Int("port", 9000, "Port to run server/client on.")
	addr := flag.String("a", "61.245.149.58", "address to connect to.")
	isServer := flag.Bool("s", false, "Set if running the server.")
	isList := flag.Bool("l", false, "Set if requesting a list")
	isReceive := flag.Bool("p", false, "Set if receiving a file")

	flag.Parse()

	if *isServer {
		log.Printf("Server running on %d\n", *port)
		s := Server{port: *port}
		s.Run()
	} else {
		log.Printf("Client running on %d\n", *port)
		c := Client{port: *port, address: *addr, list: *isList, receive: *isReceive}
		err := c.Connect()
		if err != nil {
			fmt.Print(err)
		}
	}
}
