package secure

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestPacketBasic(t *testing.T) {
	// pSrc := PacketStart{
	// 	OperationType:   0,
	// 	ClientName:      "test1",
	// 	ProtocolVersion: "test2",
	// 	AuthToken:       "test3",
	// }
	// pDst := PacketStart{}

	// buf := bytes.Buffer{}

	srcConn, dstConn := net.Pipe()

	srcSecConn := SecureConnection{
		Conn: srcConn,
		SharedKey: &[32]byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
			0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
			0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
			0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
		},
		Buffer: &bytes.Buffer{},
	}

	dstSecConn := SecureConnection{
		Conn: dstConn,
		SharedKey: &[32]byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
			0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
			0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
			0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
		},
		Buffer: &bytes.Buffer{},
	}

	testData := [][]byte{
		[]byte("HELLOGDIJFDGIOJDFGOIJGFDOIJGFDOI"),
		[]byte("Ἰοὺ ἰού· τὰ πάντʼ ἂν ἐξήκοι σαφῆ"),
	}

	big := []byte{}
	for i := 0; i < 400; i++ {
		big = append(big, 0xdd)
	}
	testData = append(testData, big)

	for _, b := range testData {

		go func() {
			srcSecConn.Write(b)
		}()

		time.Sleep(time.Second)

		out := make([]byte, 16384)
		n, err := dstSecConn.Read(out)
		if err != nil {
			t.Errorf("got error %v", err)
		}
		if n != len(b) {
			t.Errorf("wrong length expected %d got %d", len(b), n)
		}
		if !bytes.Equal(out[:n], b) {
			t.Errorf("%v not equal to %v", out[:n], b)
		}
	}

}

func BenchmarkPPS(b *testing.B) {
	srcConn, dstConn := net.Pipe()

	srcSecConn := SecureConnection{
		Conn: srcConn,
		SharedKey: &[32]byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
			0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
			0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
			0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
		},
		Buffer: &bytes.Buffer{},
	}

	dstSecConn := SecureConnection{
		Conn: dstConn,
		SharedKey: &[32]byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
			0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
			0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
			0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
		},
		Buffer: &bytes.Buffer{},
	}

	testdata := []byte{}
	for i := 0; i < 1024; i++ {
		testdata = append(testdata, 0xdd)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {

		go func() {
			srcSecConn.Write(testdata)
		}()

		out := make([]byte, 16384)
		n, err := dstSecConn.Read(out)

		if err != nil {
			b.Errorf("got error %v", err)
		}
		if n != len(testdata) {
			b.Errorf("wrong length expected %d got %d", len(testdata), n)
		}
		if !bytes.Equal(out[:n], testdata) {
			b.Errorf("%v not equal to %v", out[:n], testdata)
		}
	}

}
