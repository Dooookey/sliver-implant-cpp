// Command mtls-testserver is an end-to-end peer for the C implant's session
// loop: TLS 1.3 mTLS + MUX/1 + yamux + signed Envelope frames.
//
// It does what a Sliver server does at the protocol level, minus the RPC:
//
//  1. TLS 1.3, client certificate required (P-521)
//  2. reads the MUX/1 preface, starts a yamux server
//  3. accepts the register stream, verifies the frame signature and prints the
//     Register fields
//  4. opens its own stream, sends a signed Envelope{Type: MsgPing}
//  5. expects the implant to answer with Envelope{ID, UnknownMessageType:true}
//
// Fixtures (CA/server/client certs) and server.pub are written to -out.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

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
	raw[0], raw[1] = 0x45, 0x64
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

func writeFrame(w io.Writer, sig, env []byte) error {
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

// envelopeFields walks a protobuf message and returns varint/length fields.
func envelopeFields(env []byte) (map[uint64]uint64, map[uint64][]byte) {
	varints := map[uint64]uint64{}
	bytesFields := map[uint64][]byte{}
	i := 0
	for i < len(env) {
		key, n := binary.Uvarint(env[i:])
		if n <= 0 {
			return varints, bytesFields
		}
		i += n
		field, wire := key>>3, key&7
		switch wire {
		case 0:
			v, n2 := binary.Uvarint(env[i:])
			if n2 <= 0 {
				return varints, bytesFields
			}
			i += n2
			varints[field] = v
		case 2:
			l, n2 := binary.Uvarint(env[i:])
			if n2 <= 0 {
				return varints, bytesFields
			}
			i += n2
			bytesFields[field] = env[i : i+int(l)]
			i += int(l)
		case 1:
			i += 8
		case 5:
			i += 4
		default:
			return varints, bytesFields
		}
	}
	return varints, bytesFields
}

type fixture struct {
	certPEM, keyPEM []byte
	cert            *x509.Certificate
	key             *ecdsa.PrivateKey
}

func newCA() (*x509.Certificate, *ecdsa.PrivateKey, *fixture, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sliver-cpp test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key, &fixture{certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert: cert, key: key}, nil
}

func issue(ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, usage x509.ExtKeyUsage) (*fixture, error) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &fixture{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		cert:    cert,
		key:     key,
	}, nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1:9446", "listen address")
	agePriv := flag.String("age-priv", "", "age private key string the implant uses")
	outDir := flag.String("out", "build/mtls-fixtures", "fixture directory")
	flag.Parse()

	if *agePriv == "" {
		log.Fatal("-age-priv is required")
	}
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		log.Fatal(err)
	}
	_, clientPub := signerFromAge(*agePriv)

	serverSeed := sha256.Sum256([]byte("sliver-mtls-test-server"))
	serverPriv := ed25519.NewKeyFromSeed(serverSeed[:])
	serverPub := serverPriv.Public().(ed25519.PublicKey)

	caCert, caKey, ca, err := newCA()
	if err != nil {
		log.Fatal(err)
	}
	server, err := issue(caCert, caKey, "sliver-cpp mtls server", x509.ExtKeyUsageServerAuth)
	if err != nil {
		log.Fatal(err)
	}
	client, err := issue(caCert, caKey, "sliver-cpp mtls client", x509.ExtKeyUsageClientAuth)
	if err != nil {
		log.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"ca.pem": ca.certPEM, "server.pem": server.certPEM, "server.key": server.keyPEM,
		"client.pem": client.certPEM, "client.key": client.keyPEM,
		"server.pub": []byte(minisignText(serverPub)),
	} {
		if err := os.WriteFile(filepath.Join(*outDir, name), data, 0o600); err != nil {
			log.Fatal(err)
		}
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{server.cert.Raw}, PrivateKey: server.key}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	ln, err := tls.Listen("tcp", *addr, cfg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("listening on %s (TLS 1.3 mTLS + yamux)\n", *addr)
	fmt.Printf("fixtures in %s\n", *outDir)

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

	if tc, ok := conn.(*tls.Conn); ok {
		if err := tc.Handshake(); err != nil {
			log.Printf("tls handshake: %v", err)
			return
		}
		cs := tc.ConnectionState()
		log.Printf("tls: %s %s client-cert=%s", tls.VersionName(cs.Version),
			tls.CipherSuiteName(cs.CipherSuite), cs.PeerCertificates[0].Subject.CommonName)
	}

	preface := make([]byte, 5)
	if _, err := io.ReadFull(conn, preface); err != nil || string(preface) != "MUX/1" {
		log.Printf("bad preface %q: %v", preface, err)
		return
	}
	log.Printf("preface ok")

	ycfg := yamux.DefaultConfig()
	ycfg.LogOutput = io.Discard
	sess, err := yamux.Server(conn, ycfg)
	if err != nil {
		log.Printf("yamux: %v", err)
		return
	}
	defer sess.Close()

	stream, err := sess.AcceptStream()
	if err != nil {
		log.Printf("accept: %v", err)
		return
	}
	sig, env, err := readFrame(stream)
	if err != nil {
		log.Printf("register frame: %v", err)
		return
	}
	if !ed25519.Verify(clientPub, env, sig[10:]) {
		log.Printf("register signature INVALID")
		return
	}
	varints, bytesFields := envelopeFields(env)
	regType := varints[2]
	if regType != 1 {
		log.Printf("expected MsgRegister(1), got %d", regType)
		return
	}
	rv, rb := envelopeFields(bytesFields[3])
	fmt.Printf("REGISTER ok: name=%q hostname=%q os=%q arch=%q pid=%d config=%q c2=%q\n",
		string(rb[1]), string(rb[2]), string(rb[7]), string(rb[8]), int64(rv[9]),
		string(rb[16]), string(rb[11]))

	// Server initiated stream -> signed Ping; the implant should answer with
	// Envelope{ID, UnknownMessageType:true}.
	srvStream, err := sess.OpenStream()
	if err != nil {
		log.Printf("open server stream: %v", err)
		return
	}
	// Envelope{ID: 12345, Type: 44 (MsgExecuteReq), Data: "x"} - a message the
	// implant does not implement, so it must answer UnknownMessageType.
	reply := []byte{0x08, 0xb9, 0x60, 0x10, 0x2c, 0x1a, 0x01, 0x78}
	if err := writeFrame(srvStream, rawSignature(serverPriv, serverPub, reply), reply); err != nil {
		log.Printf("write ping: %v", err)
		return
	}
	log.Printf("sent signed Ping on server stream %d", srvStream.StreamID())

	sig2, env2, err := readFrame(srvStream)
	if err != nil {
		log.Printf("no reply from implant: %v", err)
		return
	}
	if !ed25519.Verify(clientPub, env2, sig2[10:]) {
		log.Printf("implant reply signature INVALID")
		return
	}
	v2, _ := envelopeFields(env2)
	fmt.Printf("IMPLANT REPLY ok: type=%d id=%d unknown-type=%d\n", v2[2], v2[1], v2[4])
	srvStream.Close()
}

