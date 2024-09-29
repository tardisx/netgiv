package secure

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	"golang.org/x/crypto/nacl/box"
)

type SecureMessage struct {
	Msg   []byte
	Size  uint16
	Nonce [24]byte
}

func (s *SecureMessage) toByteArray() []byte {
	length := []byte{0x0, 0x0}
	binary.BigEndian.PutUint16(length, uint16(len(s.Msg)))
	out := append(s.Nonce[:], length...)
	out = append(out, s.Msg[:]...)
	return out
}

func DeterminePacketSize(data []byte) uint16 {
	// first 24 bytes are the nonce, then the size
	if len(data) < 26 {
		return 0
	}
	size := binary.BigEndian.Uint16(data[24:26])
	size += 26 // add the length header and the nonce
	return size
}

func ConstructSecureMessage(sm []byte) SecureMessage {
	var nonce [24]byte
	nonceArray := sm[:24]
	size := binary.BigEndian.Uint16(sm[24:26])
	copy(nonce[:], nonceArray)

	// Trim out all unnecessary bytes
	// msg := bytes.Trim(sm[24:], "\x00")

	return SecureMessage{Msg: sm[26 : 26+size], Size: size, Nonce: nonce}
}

type SecureConnection struct {
	// Conn      *net.TCPConn
	Conn      io.ReadWriteCloser
	SharedKey *[32]byte
	Buffer    *bytes.Buffer
}

func (s *SecureConnection) Read(p []byte) (int, error) {
	message := make([]byte, 2048)
	// Read the message from the buffer
	eof := false

	outputBytes := make([]byte, 0)

	n, err := s.Conn.Read(message)

	if err != nil && err != io.EOF {
		log.Errorf("read: error in connection read %v", err)
		return 0, err
	}
	if err == io.EOF {
		eof = true
	}
	s.Buffer.Write(message[:n])

	for {

		actualPacketEnd := DeterminePacketSize(s.Buffer.Bytes())
		if actualPacketEnd == 0 {
			break
		}

		// our buffer contains a partial packet
		if int(actualPacketEnd) > len(s.Buffer.Bytes()) {
			break
		}

		encryptedBytes := make([]byte, actualPacketEnd)
		n, err := s.Buffer.Read(encryptedBytes)
		if err != nil && err != io.EOF {
			log.Errorf("failed to get encrypted bytes from buffer?")
			return 0, errors.New("failed to get encrypted bytes from buffer")
		}
		if n != int(actualPacketEnd) {
			log.Errorf("failed to get right number of encrypted bytes from buffer")
			return 0, errors.New("failed to get right number of encrypted bytes from buffer")

		}
		secureMessage := ConstructSecureMessage(encryptedBytes)
		// log.Printf("Secure message from wire bytes: \n  nonce: %v\n  msg: %v\n  size: %d\n", secureMessage.Nonce, secureMessage.Msg, secureMessage.Size)
		decryptedMessage, ok := box.OpenAfterPrecomputation(nil, secureMessage.Msg, &secureMessage.Nonce, s.SharedKey)

		if !ok {
			return 0, errors.New("problem decrypting the message")
		}

		outputBytes = append(outputBytes, decryptedMessage...)

		if eof && s.Buffer.Len() == 0 {
			log.Debugf("returning the final packet")
			break
		}

	}

	err = io.EOF
	if !eof {
		err = nil
	}

	copy(p, outputBytes)

	return len(outputBytes), err
}

func (s *SecureConnection) Write(p []byte) (int, error) {
	var nonce [24]byte

	// Create a new nonce for each message sent
	_, _ = rand.Read(nonce[:])

	encryptedMessage := box.SealAfterPrecomputation(nil, p, &nonce, s.SharedKey)
	sm := SecureMessage{Msg: encryptedMessage, Nonce: nonce}

	// Write it to the connection
	wireBytes := sm.toByteArray()

	return s.Conn.Write(wireBytes)
}

func Handshake(conn *net.TCPConn) *[32]byte {
	var peerKey, sharedKey [32]byte

	publicKey, privateKey, _ := box.GenerateKey(rand.Reader)

	_, _ = conn.Write(publicKey[:])

	peerKeyArray := make([]byte, 32)
	_, _ = conn.Read(peerKeyArray)
	copy(peerKey[:], peerKeyArray)

	box.Precompute(&sharedKey, &peerKey, privateKey)

	return &sharedKey
}

type OperationTypeEnum byte

const (
	OperationTypeSend OperationTypeEnum = iota
	OperationTypeList
	OperationTypeReceive
	OperationTypeBurn
)

// PacketStartRequest is sent from the client to the server at the beginning
// to authenticate and announce the requested particular operation
type PacketStartRequest struct {
	OperationType   OperationTypeEnum
	ClientName      string
	ProtocolVersion string
	AuthToken       string
}

type PacketStartResponseEnum byte

const (
	// Client can connect
	PacketStartResponseEnumOK PacketStartResponseEnum = iota
	// Client using wrong protocol version
	PacketStartResponseEnumWrongProtocol
	// Client supplied bad auth token
	PacketStartResponseEnumBadAuthToken
)

type PacketStartResponse struct {
	Response PacketStartResponseEnum
}

type PacketSendDataStart struct {
	Filename  string
	TotalSize uint32
}
type PacketSendDataNext struct {
	Size uint16
	Data []byte
}

// PacketReceiveDataStart is sent from the server to the client when
// the client asks for a file to be sent to them.
type PacketReceiveDataStartRequest struct {
	Id uint32
}

type PacketReceiveDataStartResponseEnum byte

const (
	// File transfer can begin
	ReceiveDataStartResponseOK PacketReceiveDataStartResponseEnum = iota
	// No such file by index
	ReceiveDataStartResponseNotFound
)

// PacketReceiveDataStartResponse is the response to the above packet.
type PacketReceiveDataStartResponse struct {
	Status    PacketReceiveDataStartResponseEnum
	Filename  string
	Kind      string
	TotalSize uint32
}

type PacketReceiveDataNext struct {
	Size uint16
	Data []byte
	Last bool
}

type PacketListData struct {
	Id        uint32
	Filename  string
	FileSize  uint32
	Timestamp time.Time
	Kind      string
}

type PacketBurnRequest struct {
	Id uint32
}

type PacketBurnResponse struct {
	Status PacketBurnResponseEnum
}

type PacketBurnResponseEnum byte

const (
	// File has been deleted
	BurnResponseOK PacketBurnResponseEnum = iota
	// No such file by index
	BurnResponseNotFound
)
