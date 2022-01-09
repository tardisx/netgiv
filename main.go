package main

import (
	"flag"
	"fmt"
)

func main() {
	port := flag.Int("p", 9000, "Port to run server/client on.")
	isServer := flag.Bool("s", false, "Set if running the server.")
	flag.Parse()

	if *isServer {
		fmt.Printf("Server running on %d\n", *port)
		s := Server{port: *port}
		s.Run()
	} else {
		fmt.Printf("Client running on %d\n", *port)
		c := Client{port: *port}
		err := c.Connect()
		if err != nil {
			fmt.Print(err)
		}
	}
}
