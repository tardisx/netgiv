package main

import (
	"fmt"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
	"golang.org/x/term"

	"github.com/mattn/go-isatty"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const ProtocolVersion = "1.1"

type ListValue struct {
	Required bool
	Number   uint
}

func (v *ListValue) String() string {
	if v.Required {
		return fmt.Sprintf("YES: %d", v.Number)
	}
	return "0"
}

func (v *ListValue) Set(s string) error {
	v.Required = true
	num, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}

	v.Number = uint(num)
	return nil
}

func (v *ListValue) Type() string {
	return "int"
}

func getAuthTokenFromTerminal() string {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0o755)
	if err != nil {
		log.Printf("cannot open /dev/tty to read authtoken: %v", err)
		return ""
	}
	fd := int(tty.Fd())

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		log.Printf("cannot set /dev/tty to raw mode: %v", err)
		return ""
	}
	defer func() {
		_ = term.Restore(fd, oldState)
	}()

	t := term.NewTerminal(tty, "")
	pass, err := t.ReadPassword("Enter auth token: ")
	if err != nil {
		log.Printf("cannot read password from /dev/tty: %v", err)
		return ""
	}

	return pass
}

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	isServer := flag.Bool("server", false, "Run netgiv in server mode")

	// client mode flags
	isList := flag.BoolP("list", "l", false, "Returns a list of current items on the server")
	isSend := flag.BoolP("copy", "c", false, "send stdin to netgiv server (copy)")

	pasteFlag := ListValue{}
	flag.VarP(&pasteFlag, "paste", "p", "receive from netgiv server to stdout (paste), with optional id (see --list)")
	flag.Lookup("paste").NoOptDefVal = "0"

	burnFlag := ListValue{}
	flag.VarP(&burnFlag, "burn", "b", "burn (remove/delete) the item on the netgiv server, with optional id (see --list)")
	flag.Lookup("burn").NoOptDefVal = "0"

	debug := flag.Bool("debug", false, "turn on debug logging")
	flag.String("address", "", "IP address/hostname of the netgiv server")

	helpConfig := flag.Bool("help-config", false, "Show help on netgiv configuration")

	// common flags
	flag.String("authtoken", "", "Authentication token")
	flag.Int("port", 0, "Port")

	versionFlag := flag.BoolP("version", "v", false, "show version and exit")

	flag.Parse()

	if versionFlag != nil && *versionFlag {
		fmt.Print(versionInfo(true))
		os.Exit(0)
	}

	receiveNum := int(pasteFlag.Number)
	if !pasteFlag.Required {
		receiveNum = -1
	}

	burnNum := int(burnFlag.Number)
	if !burnFlag.Required {
		burnNum = -1
	}

	viper.AddConfigPath("$HOME/.netgiv/")
	viper.AddConfigPath("$HOME/.config/netgiv/") // calling multiple times adds to search paths
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

	_ = viper.BindPFlags(flag.CommandLine)

	viper.SetEnvPrefix("NETGIV")
	_ = viper.BindEnv("authtoken")

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

	// if still no authtoken and in client mode, try from the terminal, last
	// ditch effort
	if !*isServer && authtoken == "" {
		authtoken = getAuthTokenFromTerminal()
	}

	if authtoken == "" {
		log.Fatal("authtoken must be set")
	}

	if !*isServer && address == "" {
		log.Fatal("an address must be provided on the command line, or configuration")
	}

	log.Debugf("protocol version: %s", ProtocolVersion)
	if *isServer {
		s := Server{port: port, authToken: authtoken}
		s.Run()
	} else {
		if !*isList && !*isSend && burnNum == -1 && receiveNum == -1 {
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

		c := Client{port: port, address: address, list: *isList, send: *isSend, burnNum: burnNum, receiveNum: receiveNum, authToken: authtoken}
		err := c.Connect()
		if err != nil {
			fmt.Print(err)
		}
	}
}

func versionInfo(verbose bool) string {
	out := ""
	out += fmt.Sprintf("netgiv %s, built at %s\n", version, date)
	if verbose {
		out += fmt.Sprintf("commit: %s\n", commit)
		out += fmt.Sprintf("http://github.com/tardisx/netgiv\n")
	}
	return out
}
