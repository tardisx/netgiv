package secure

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"

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
	Conn      *net.TCPConn
	SharedKey *[32]byte
	Buffer    *bytes.Buffer
}

func (s *SecureConnection) Read(p []byte) (int, error) {
	message := make([]byte, 2048)
	// Read the message from the buffer
	eof := false

	outputBytes := make([]byte, 0)

	// log.Printf("READ: start, p %d/%d, buffer contains currently contains %d bytes", len(p), cap(p), s.Buffer.Len())

	n, err := s.Conn.Read(message)

	if err != nil && err != io.EOF {
		log.Printf("read: error in connection read %v", err)
		return 0, err
	}
	if err == io.EOF {
		eof = true
	}

	// log.Printf("read: got %d bytes on the wire, error is %v", n, err)
	// log.Printf("looks like %v", message[:n])
	if eof {
		log.Printf("eof is true - this is our final read!")
	}

	s.Buffer.Write(message[:n])
	// log.Printf("read: appended them to the buffer which is now %d bytes", len(s.Buffer.Bytes()))

	for {

		actualPacketEnd := DeterminePacketSize(s.Buffer.Bytes())
		if actualPacketEnd == 0 {
			// log.Printf("packet too small?")
			break
			return 0, io.EOF
		}

		if int(actualPacketEnd) > len(s.Buffer.Bytes()) {
			// we must have half a packet
			// log.Print("partial packet detected")
			break
		}

		secureMessage := ConstructSecureMessage(s.Buffer.Bytes()[:actualPacketEnd])
		// log.Printf("Secure message from wire bytes: \n  nonce: %v\n  msg: %v\n  size: %d\n", secureMessage.Nonce, secureMessage.Msg, secureMessage.Size)
		decryptedMessage, ok := box.OpenAfterPrecomputation(nil, secureMessage.Msg, &secureMessage.Nonce, s.SharedKey)

		if !ok {
			return 0, errors.New("problem decrypting the message")
		}

		outputBytes = append(outputBytes, decryptedMessage...)

		// log.Printf("OUT now: %d bytes", len(outputBytes))
		// copy(p, decryptedMessage)

		// trim what we used off the buffer
		newBuffer := s.Buffer.Bytes()[actualPacketEnd:]
		s.Buffer = bytes.NewBuffer(newBuffer)

		if eof && s.Buffer.Len() == 0 {
			log.Printf("returning the final packet")
			break
		}

	}

	err = io.EOF
	if !eof {
		err = nil
	}

	copy(p, outputBytes)

	// log.Printf("returning %d decrypted bytes with err: %w", len(outputBytes), err)
	// log.Printf("READ: end, p %d/%d, buffer contains currently contains %d bytes", len(p), cap(p), s.Buffer.Len())

	return len(outputBytes), err
}

func (s *SecureConnection) Write(p []byte) (int, error) {
	// func (s *SecureConnection) Write(o encoding.BinaryMarshaler) (int, error) {
	var nonce [24]byte

	// Create a new nonce for each message sent
	rand.Read(nonce[:])
	// log.Printf("before encryption it is %d bytes", len(p))
	encryptedMessage := box.SealAfterPrecomputation(nil, p, &nonce, s.SharedKey)
	sm := SecureMessage{Msg: encryptedMessage, Nonce: nonce}

	// Write it to the connection
	wireBytes := sm.toByteArray()
	// log.Printf("putting %d bytes on the wire\n  nonce: %v\n  bytes: %v", len(wireBytes), nonce, wireBytes)
	return s.Conn.Write(wireBytes)
}

func Handshake(conn *net.TCPConn) *[32]byte {
	var peerKey, sharedKey [32]byte

	log.Print("starting handshake")
	publicKey, privateKey, _ := box.GenerateKey(rand.Reader)

	conn.Write(publicKey[:])

	peerKeyArray := make([]byte, 32)
	conn.Read(peerKeyArray)
	copy(peerKey[:], peerKeyArray)

	box.Precompute(&sharedKey, &peerKey, privateKey)

	log.Printf("ending handshake, sk: %v", sharedKey)

	return &sharedKey
}

type OperationTypeEnum byte

const (
	OperationTypeSend OperationTypeEnum = iota
)

// PacketStart is sent from the client to the server at the beginning
// to authenticate and annonce the requested particular operation
type PacketStart struct {
	OperationType   OperationTypeEnum
	ClientName      string
	ProtocolVersion string
	AuthToken       string
}

type PacketSendDataStart struct {
	Filename  string
	TotalSize uint32
}

type PacketSendDataNext struct {
	Size uint16
	Data []byte
}
