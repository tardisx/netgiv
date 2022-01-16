package main

import (
	"flag"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/mattn/go-isatty"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func main() {
	// log.SetFlags(log.Lshortfile)
	flag.Int("port", 4912, "Port to run server/client on.")
	addr := flag.String("a", "127.0.0.1", "address to connect to.")
	isServer := flag.Bool("s", false, "Set if running the server.")
	isList := flag.Bool("l", false, "Set if requesting a list")
	isSend := flag.Bool("c", false, "Set if sending a file (copy)")
	isReceive := flag.Bool("p", false, "Set if receiving a file (paste)")

	flag.Parse()

	viper.SetDefault("port", 4512)

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	port := viper.GetInt("port") // retrieve value from viper

	if *isServer {

		log.Printf("Server running on %d\n", port)
		s := Server{port: port}
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
			} else if !stdinTTY && !stdoutTTY {
				log.Fatal("I can't cope with both stdin and stdout being pipes")
			}

		}

		if !*isList && !*isSend && !*isReceive {
			// could default to list?
			*isList = true
		}

		c := Client{port: port, address: *addr, list: *isList, send: *isSend, receive: *isReceive}
		err := c.Connect()
		if err != nil {
			fmt.Print(err)
		}
	}
}
