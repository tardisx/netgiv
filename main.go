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
	// flag.Int("port", 4912, "Port to run server/client on.")
	// addr := flag.String("a", "127.0.0.1", "address to connect to.")
	isServer := flag.Bool("s", false, "Run netgiv in server mode")

	// client mode flags
	isList := flag.Bool("l", false, "Set if requesting a list")
	isSend := flag.Bool("c", false, "sending stdin to netgiv server (copy)")
	isReceive := flag.Bool("p", false, "receive file from netgiv server to stdout (paste)")
	flag.String("address", "", "IP address/hostname of the netgiv server")

	helpConfig := flag.Bool("help-config", false, "Show help on netgiv configuration")

	// common flags
	flag.String("authtoken", "", "Authentication token")
	flag.Int("port", 0, "Port")

	flag.Parse()

	viper.AddConfigPath("$HOME/.netgiv/") // call multiple times to add many search paths
	viper.SetConfigType("yaml")

	viper.SetDefault("port", 4512)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// no config file maybe that's ok
			panic(err)
		} else {
			// Config file was found but another error was produced
			log.Fatal(err)
		}
	}

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	viper.SetEnvPrefix("NETGIV")
	viper.BindEnv("authtoken")

	// pull the various things into local variables
	port := viper.GetInt("port") // retrieve value from viper
	authtoken := viper.GetString("authtoken")

	if authtoken == "" {
		log.Fatal("authtoken must be set")
	}

	address := viper.GetString("address")
	if !*isServer && address == "" {
		log.Fatal("an address must be provided on the command line, or configuration")
	}

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Printf("\nIf stdin or stdout is a pipe, %s will automatically choose an appropriate\n", os.Args[0])
		fmt.Printf("copy (-c) or paste (-p) mode\n")
	}

	if *helpConfig {
		fmt.Print(
			`netgiv can be configured by command line parameters (see --help)  but it will
often be convenient to create a config file. The config file is in yaml format,
and should be stored in $HOME/.netgiv/config.yaml.

For both client and server, you will want to set the 'authtoken' key (they must
match). You'll want to also set the 'port' key if you would like to run netgiv 
on a non-standard port (the default is 4512).

On the client you will probably want to set the 'address' key, so that your client
knows where to find the netgiv server. This key is ignored when running in server
mode.

Example:

port: 5412
authtoken: verysecretvaluehere
address: 10.1.12.20

Note that it is possible to set/override the authtoken by setting the NETGIV_AUTHTOKEN
environment variable. This may be preferable in some environments.

`)
		os.Exit(1)

	}

	if *isServer {
		s := Server{port: port, authToken: authtoken}
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
			} else {
				flag.Usage()
				os.Exit(1)
			}

		}

		c := Client{port: port, address: address, list: *isList, send: *isSend, receive: *isReceive, authToken: authtoken}
		err := c.Connect()
		if err != nil {
			fmt.Print(err)
		}
	}
}
