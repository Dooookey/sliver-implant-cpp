// Command yamux-testserver is a throw-away interop peer for the C implant's
// yamux + signed-frame layer (no Sliver server needed).
//
// Protocol on the wire (plain TCP, no TLS - the TLS path is tested separately):
//
//	client: "MUX/1"
//	client: yamux stream -> [74B ed25519 sig][u32 LE len][Envelope]
//	server: yamux stream -> [74B ed25519 sig][u32 LE len][Envelope{Ping}]
//
// The server derives its expected client public key from the same age private
// key string the C side uses ("env-signing-v1:" + privKey => ed25519 seed) and
// writes its own minisign public key text to <out>/server.pub for the client.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/blake2b"
)

func signerFromAge(agePriv string) (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := sha256.Sum256([]byte("env-signing-v1:" + agePriv))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv, priv.Public().(ed25519.PublicKey)
}

func minisignText(pub ed25519.PublicKey) string {
	digest := blake2b.Sum256(pub)
	keyID := binary.LittleEndian.Uint64(digest[:8])
	raw := make([]byte, 42)
	raw[0], raw[1] = 0x45, 0x64 // 0x6445 LE
	binary.LittleEndian.PutUint64(raw[2:], keyID)
	copy(raw[10:], pub)
	return fmt.Sprintf("untrusted comment: minisign public key: %016X\n%s\n",
		keyID, base64.StdEncoding.EncodeToString(raw))
}

func rawSignature(priv ed25519.PrivateKey, pub ed25519.PublicKey, msg []byte) []byte {
	digest := blake2b.Sum256(pub)
	sig := make([]byte, 74)
	binary.LittleEndian.PutUint16(sig, 0x6445)
	binary.LittleEndian.PutUint64(sig[2:], binary.LittleEndian.Uint64(digest[:8]))
	copy(sig[10:], ed25519.Sign(priv, msg))
	return sig
}

func readFrame(r io.Reader) ([]byte, []byte, error) {
	sig := make([]byte, 74)
	if _, err := io.ReadFull(r, sig); err != nil {
		return nil, nil, err
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, nil, err
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n == 0 || n > 8<<20 {
		return nil, nil, fmt.Errorf("bad frame length %d", n)
	}
	env := make([]byte, n)
	if _, err := io.ReadFull(r, env); err != nil {
		return nil, nil, err
	}
	return sig, env, nil
}

func writeFrame(w io.Writer, sig []byte, env []byte) error {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(env)))
	if _, err := w.Write(sig); err != nil {
		return err
	}
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(env)
	return err
}

// envelopeType pulls field 2 (uint32 Type) out of the protobuf without a
// descriptor, enough for a log line.
func envelopeType(env []byte) uint32 {
	i := 0
	for i < len(env) {
		key, n := binary.Uvarint(env[i:])
		if n <= 0 {
			return 0
		}
		i += n
		field := key >> 3
		wire := key & 7
		switch wire {
		case 0:
			v, n2 := binary.Uvarint(env[i:])
			if n2 <= 0 {
				return 0
			}
			i += n2
			if field == 2 {
				return uint32(v)
			}
		case 2:
			l, n2 := binary.Uvarint(env[i:])
			if n2 <= 0 {
				return 0
			}
			i += n2 + int(l)
		case 1:
			i += 8
		case 5:
			i += 4
		default:
			return 0
		}
	}
	return 0
}

func main() {
	addr := flag.String("addr", "127.0.0.1:9444", "listen address")
	agePriv := flag.String("age-priv", "", "age private key string the C side uses for its signing seed")
	outDir := flag.String("out", "build/yamux-fixtures", "where to write server.pub")
	flag.Parse()

	if *agePriv == "" {
		log.Fatal("-age-priv is required")
	}
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		log.Fatal(err)
	}
	_, clientPub := signerFromAge(*agePriv)

	serverSeed := make([]byte, 32)
	if _, err := rand.Read(serverSeed); err != nil {
		log.Fatal(err)
	}
	serverPriv := ed25519.NewKeyFromSeed(serverSeed)
	serverPub := serverPriv.Public().(ed25519.PublicKey)
	pubText := minisignText(serverPub)
	if err := os.WriteFile(filepath.Join(*outDir, "server.pub"), []byte(pubText), 0o600); err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("listening on %s (yamux interop)\n", *addr)
	fmt.Printf("server minisign key: %s\n", filepath.Join(*outDir, "server.pub"))

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn, clientPub, serverPriv, serverPub)
	}
}

func handle(conn net.Conn, clientPub ed25519.PublicKey, serverPriv ed25519.PrivateKey, serverPub ed25519.PublicKey) {
	defer conn.Close()

	preface := make([]byte, 5)
	if _, err := io.ReadFull(conn, preface); err != nil || string(preface) != "MUX/1" {
		log.Printf("bad preface %q: %v", preface, err)
		return
	}
	log.Printf("preface ok")

	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	sess, err := yamux.Server(conn, cfg)
	if err != nil {
		log.Printf("yamux server: %v", err)
		return
	}
	defer sess.Close()

	stream, err := sess.AcceptStream()
	if err != nil {
		log.Printf("accept stream: %v", err)
		return
	}
	log.Printf("stream %d accepted", stream.StreamID())

	sig, env, err := readFrame(stream)
	if err != nil {
		log.Printf("read frame: %v", err)
		return
	}
	if !ed25519.Verify(clientPub, env, sig[10:]) {
		log.Printf("client frame signature INVALID")
		return
	}
	log.Printf("client frame ok: type=%d len=%d", envelopeType(env), len(env))

	// Reply with a signed Envelope{Type: MsgPing, Data: Ping{nonce: 31337}}.
	ping := []byte{0x08, 0xe9, 0xf4, 0x01} // field1 varint 31337
	reply := []byte{0x10, 0x03, 0x1a, byte(len(ping))} // type=3, data=ping
	reply = append(reply, ping...)
	if err := writeFrame(stream, rawSignature(serverPriv, serverPub, reply), reply); err != nil {
		log.Printf("write reply: %v", err)
		return
	}
	stream.Close()
	log.Printf("reply sent (Ping, signed)")
	_ = sess.Close()
}


