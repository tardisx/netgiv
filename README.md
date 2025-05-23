# ARCHIVED - 2025-05-23

Due to GitHub's AI enshittification, this project has been moved to https://code.ppl.town/justin/netgiv

# netgiv

## What is this?

`netgiv` is a single binary client and server to facilitate sending files across
your local network quickly and easily.

It uses a familiar unix pipeline paradigm, so files can be moved between machines
as part of a pipeline, obviating the need for dealing with temporary files.

`netgiv` automatically detects "copy" (stdin is a pipe) or "paste" (stdout is a
pipe) modes, allowing intuitive use like:

    hostA$ pg_dumpall | netgiv

    hostB$ netgiv | psql restoredb

Note that since netgiv uses a persistent server, there is no need to setup both ends
of the pipeline in advance (compared to netcat or similar tools).

This also means that you could "copy" once and "paste" multiple times, on
multiple different machines.

All data is encrypted in flight (though not in the temporary files on the server)
Access to the server is granted by an authentication token (preshared key) of your
choice.

## Install

### Binary release

Grab the appropriate version from https://github.com/tardisx/netgiv/releases, unzip
and place the binary somewhere on your $PATH.

### Compiling from source

    go install github.com/tardisx/netgiv@latest

`netgiv` should end up on your go binary path.

### Compiling from source

Clone this repository, run `go build`.

## Configuration

Configuration of `netgiv` is via a YAML configuration file in
`$HOME/.netgiv/config.yaml`.

Run `netgiv --help-config` to see a sample config file.

The server requires the 'authtoken' and 'port' configuration keys to be set.

The client requires the 'authtoken', 'port' and 'address' configuration keys to be 
set.

* `authtoken` - this is any arbitrary string, you should choose something not easy to
  guess
* `port` - this is the TCP port the server will listen on (and that the client will
  connect to)
* `address` - the IP address or hostname of the `netgiv` server

## Running


### Server

To run a server, just run:

    netgiv --server

`netgiv` will run in the foreground and log accesses to it.

### Client

#### Copy

On any client, run:

    $ echo "Hello" | netgiv

To check for success, try:

    $ netgiv | cat

You should see "hello" echoed on your terminal.

#### List

To check the list of files on the server:

    $ netgiv -l
    1: UTF-8 text (6 B)
    2: application/x-mach-binary (6.5 MB)
    3: video/quicktime (14 MB)
    4: image/png (1.5 MB)

Note that netgiv tries to identify each file based on file magic heuristics.

#### Paste

If you would like to fetch (paste) a particular file:

    netgiv -p 3 > file.mov

Where '3' comes from the information provided in the `-l` output.

Note that providing no `-p` option is the same as `-p X` where X is the highest
numbered upload (most recent).

#### Burn

If you would like to remove/delete (burn) a particular file:

    netgiv -b 3

Where '3' comes from the information provided in the `-l` output.

### Notes on output

Since netgiv is designed to be used in a pipeline, it does not provide any
output on successful execution (apart from your actual data on stdout of course!)

If you'd like to see debugging information, use the `--debug` flag.

Note that `netgiv` will send error logs to stderr in cases of problems.

### Alternative ways of providing the authtoken

It's possible that you do not trust the hosts you are running the `netgiv` client on,
or otherwise not want to store your authtoken in a file on there. If that is the case
there are a couple of alternate options:

#### ENV var

The environment variable NETGIV_AUTHTOKEN can be used to provide the authtoken. A
common way to leverage this is to send it when you ssh to a remote host via the
`SendEnv` option (see your ssh_config man page).

#### Interactive

If the authtoken has not been set by any of the above methods, it will be prompted
for interactively (it will not be echoed to the screen). Note that this only applies
to the client - the server must have a config file with an authtoken specified.

# Other notes

## Temporary file storage

The `netgiv` server will store files in your normal system temporary dir. These files 
are *not* encrypted. They will be deleted when the server shuts down (SIGTERM). If you
want or need to remove the files before the server shuts down, you can use the 
[burn](#burn) flag.

## Window support

Windows support is marginal, at best, mostly because of the lack of POSIX style 
pipes. Bug reports and suggestions for workarounds are welcome.

# Acknowledgements

* thanks to tengig for the name
* thanks to [@jsnfwlr](https://github.com/jsnfwlr) for the burn feature
