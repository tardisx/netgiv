package main

import (
	"fmt"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/mattn/go-isatty"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var CurrentVersion = "v0.0.2"

type PasteValue struct {
	PasteRequired bool
	PasteNumber   uint
}

func (v *PasteValue) String() string {
	if v.PasteRequired {
		return fmt.Sprintf("YES: %d", v.PasteNumber)
	}
	return "0"
}

func (v *PasteValue) Set(s string) error {
	v.PasteRequired = true
	num, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}

	v.PasteNumber = uint(num)
	return nil
}

func (v *PasteValue) Type() string {
	return "int"

}

func main() {
	isServer := flag.Bool("server", false, "Run netgiv in server mode")

	// client mode flags
	isList := flag.BoolP("list", "l", false, "Returns a list of current items on the server")
	isSend := flag.BoolP("copy", "c", false, "sending stdin to netgiv server (copy)")

	pasteFlag := PasteValue{}
	flag.VarP(&pasteFlag, "paste", "p", "receive from netgiv server to stdout (paste), with optional number (see --list)")
	flag.Lookup("paste").NoOptDefVal = "0"

	debug := flag.Bool("debug", false, "turn on debug logging")
	flag.String("address", "", "IP address/hostname of the netgiv server")

	helpConfig := flag.Bool("help-config", false, "Show help on netgiv configuration")

	// common flags
	flag.String("authtoken", "", "Authentication token")
	flag.Int("port", 0, "Port")

	flag.Parse()

	receiveNum := int(pasteFlag.PasteNumber)
	if !pasteFlag.PasteRequired {
		receiveNum = -1
	}

	viper.AddConfigPath("$HOME/.netgiv/") // call multiple times to add many search paths
	viper.SetConfigType("yaml")

	viper.SetDefault("port", 4512)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// don't worry be happy
		} else {
			// Config file was found but another error was produced
			log.Fatal(err)
		}
	}

	flag.Parse()
	viper.BindPFlags(flag.CommandLine)

	viper.SetEnvPrefix("NETGIV")
	viper.BindEnv("authtoken")

	// pull the various things into local variables
	port := viper.GetInt("port") // retrieve value from viper
	authtoken := viper.GetString("authtoken")

	address := viper.GetString("address")

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

	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	if authtoken == "" {
		log.Fatal("authtoken must be set")
	}

	if !*isServer && address == "" {
		log.Fatal("an address must be provided on the command line, or configuration")
	}

	if *isServer {
		s := Server{port: port, authToken: authtoken}
		s.Run()
	} else {
		if !*isList && !*isSend && receiveNum == -1 {
			// try to work out the intent based on whether or not stdin/stdout
			// are ttys
			stdinTTY := isatty.IsTerminal(os.Stdin.Fd())
			stdoutTTY := isatty.IsTerminal(os.Stdout.Fd())

			if stdinTTY && !stdoutTTY {
				receiveNum = 0
			} else if !stdinTTY && stdoutTTY {
				*isSend = true
			} else if !stdinTTY && !stdoutTTY {
				log.Fatal("I can't cope with both stdin and stdout being pipes")
			} else {
				flag.Usage()
				os.Exit(1)
			}

		}

		c := Client{port: port, address: address, list: *isList, send: *isSend, receiveNum: receiveNum, authToken: authtoken}
		err := c.Connect()
		if err != nil {
			fmt.Print(err)
		}
	}
}
