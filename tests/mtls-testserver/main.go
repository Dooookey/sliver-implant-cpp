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
	"strconv"
	"strings"
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

func caSubject(emptyName bool) pkix.Name {
	if emptyName {
		return pkix.Name{}
	}
	return pkix.Name{CommonName: "sliver-cpp test CA"}
}

func newCA(emptyName bool) (*x509.Certificate, *ecdsa.PrivateKey, *fixture, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               caSubject(emptyName),
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
	emptyCA := flag.Bool("empty-ca", false, "generate the CA with an empty subject/issuer (Sliver style)")
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

	caCert, caKey, ca, err := newCA(*emptyCA)
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

	// RPC: MsgLsReq(5) with LsReq{Path:"."} - the implant must answer with\r
	// MsgLs(6) carrying the directory listing.
	lsStream, err := sess.OpenStream()
	if err != nil {
		log.Printf("open ls stream: %v", err)
		return
	}
	lsReq := append([]byte{0x0a, 0x01, 0x2e}, 0x4a, 0x00) // Path "." + empty Request
	lsEnv := append([]byte{0x08, 0x2a, 0x10, 0x05, 0x1a, byte(len(lsReq))}, lsReq...)
	if err := writeFrame(lsStream, rawSignature(serverPriv, serverPub, lsEnv), lsEnv); err != nil {
		log.Printf("write ls req: %v", err)
		return
	}
	respStream, err := sess.AcceptStream()
	if err != nil {
		log.Printf("accept ls response stream: %v", err)
		return
	}
	lsSig, lsResp, err := readFrame(respStream)
	if err != nil {
		log.Printf("no ls response: %v", err)
		return
	}
	if !ed25519.Verify(clientPub, lsResp, lsSig[10:]) {
		log.Printf("ls response signature INVALID")
		return
	}
	lv, lb := envelopeFields(lsResp)
	if lv[2] != 6 {
		log.Printf("expected MsgLs(6), got %d", lv[2])
		return
	}
	path, files := parseLs(lb[3])
	fmt.Printf("LS ok: id=%d path=%q entries=%d first=%v\n", lv[1], path, len(files), firstN(files, 3))
	lsStream.Close()

	// RPC: MsgPwdReq(12) -> MsgPwd(13) with the working directory.
	pwdStream, err := sess.OpenStream()
	if err != nil {
		log.Printf("open pwd stream: %v", err)
		return
	}
	pwdEnv := []byte{0x08, 0x2b, 0x10, 0x0c, 0x1a, 0x02, 0x4a, 0x00}
	if err := writeFrame(pwdStream, rawSignature(serverPriv, serverPub, pwdEnv), pwdEnv); err != nil {
		log.Printf("write pwd req: %v", err)
		return
	}
	pwdRespStream, err := sess.AcceptStream()
	if err != nil {
		log.Printf("accept pwd response stream: %v", err)
		return
	}
	pwdSig, pwdResp, err := readFrame(pwdRespStream)
	if err != nil {
		log.Printf("no pwd response: %v", err)
		return
	}
	if !ed25519.Verify(clientPub, pwdResp, pwdSig[10:]) {
		log.Printf("pwd response signature INVALID")
		return
	}
	pv, pb := envelopeFields(pwdResp)
	_, pwdBody := envelopeFields(pb[3])
	fmt.Printf("PWD ok: type=%d id=%d cwd=%q\n", pv[2], pv[1], string(pwdBody[1]))
	pwdStream.Close()

	// Cd / Mkdir / Ps / Env / Rm through the generic helper.
	if _, cdBody, err := rpcCall(sess, serverPriv, serverPub, clientPub, 44, 11, protoStr(1, "."), 13); err != nil {
		log.Printf("cd failed: %v", err)
	} else {
		_, cb := envelopeFields(cdBody[3])
		fmt.Printf("CD ok: cwd=%q\n", string(cb[1]))
	}
	if _, mkBody, err := rpcCall(sess, serverPriv, serverPub, clientPub, 45, 16, protoStr(1, "build/rpc-tmp"), 17); err != nil {
		log.Printf("mkdir failed: %v", err)
	} else {
		_, mb := envelopeFields(mkBody[3])
		fmt.Printf("MKDIR ok: path=%q\n", string(mb[1]))
	}
	if _, psBody, err := rpcCall(sess, serverPriv, serverPub, clientPub, 46, 18, nil, 19); err != nil {
		log.Printf("ps failed: %v", err)
	} else {
		_, pb2 := envelopeFields(psBody[3])
		count := 0
		for i := 0; i+1 < len(pb2[1]); {
			break
		}
		// count repeated field 3 (Processes) by scanning the message
		count = countRepeated(psBody[3])
		fmt.Printf("PS ok: processes=%d\n", count)
	}
	if _, envBody, err := rpcCall(sess, serverPriv, serverPub, clientPub, 47, 66, nil, 67); err != nil {
		log.Printf("env failed: %v", err)
	} else {
		fmt.Printf("ENV ok: variables=%d\n", countRepeated(envBody[3]))
	}
	if _, rmBody, err := rpcCall(sess, serverPriv, serverPub, clientPub, 48, 14, append(protoStr(1, "build/rpc-tmp"), 0x10, 0x01), 15); err != nil {
		log.Printf("rm failed: %v", err)
	} else {
		_, rb := envelopeFields(rmBody[3])
		fmt.Printf("RM ok: path=%q\n", string(rb[1]))
	}

	// Upload -> Download -> Execute roundtrip. Absolute paths: the implant's CWD
	// is whatever directory the test process started in.
	wd, _ := os.Getwd()
	tmpFile := filepath.Join(wd, "build", "rpc-upload.txt")
	_ = os.MkdirAll(filepath.Join(wd, "build"), 0o755)
	_ = os.Remove(tmpFile)
	payload := []byte("hello rpc\n")
	upReq := append(protoStr(1, tmpFile), protoStrBytes(3, payload)...)
	if _, upBody, err := rpcCall(sess, serverPriv, serverPub, clientPub, 49, 9, upReq, 10); err != nil {
		log.Printf("upload failed: %v", err)
	} else {
		v, _ := envelopeFields(upBody[3])
		_, ub := envelopeFields(upBody[3])
		_, ur := envelopeFields(ub[9])
		fmt.Printf("UPLOAD ok: written=%d bytes-on-disk=%d err=%q\n", v[2], fileSize(tmpFile), string(ur[1]))
	}
	dlReq := protoStr(1, tmpFile)
	if _, dlBody, err := rpcCall(sess, serverPriv, serverPub, clientPub, 50, 7, dlReq, 8); err != nil {
		log.Printf("download failed: %v", err)
	} else {
		_, db := envelopeFields(dlBody[3])
		fmt.Printf("DOWNLOAD ok: exists=%v bytes=%d payload=%q\n",
			string(db[6]) == string(payload), len(db[6]), string(db[6]))
	}
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	if _, statErr := os.Stat(cmdExe); statErr != nil {
		log.Printf("cmd.exe missing (%q): %v", cmdExe, statErr)
	}
	exReq := append(protoStr(1, "cmd"), protoStr(2, "/c")...)
	exReq = append(exReq, protoStr(2, "exit 3")...)
	exReq = append(exReq, 0x18, 0x01) // Output = true
	// Long running execute must not block the session: send it, then verify Ls
	// still answers, then collect the Execute response.
	slowReq := append(protoStr(1, cmdExe), protoStr(2, "/c")...)
	slowReq = append(slowReq, protoStr(2, "powershell -c \"Start-Sleep 3; Write-Output slow-done\"")...)
	slowReq = append(slowReq, 0x18, 0x01)
	slowEnv := makeEnvelope(60, 44, slowReq)
	if st, err := sess.OpenStream(); err == nil {
		_ = writeFrame(st, rawSignature(serverPriv, serverPub, slowEnv), slowEnv)
	}
	// Concurrent Pwd while the slow execute runs: both answers must arrive.
	if st2, err := sess.OpenStream(); err == nil {
		pwdEnv := makeEnvelope(61, 12, []byte{0x4a, 0x00})
		_ = writeFrame(st2, rawSignature(serverPriv, serverPub, pwdEnv), pwdEnv)
	}
	for i := 0; i < 40; i++ {
		rs, err := sess.AcceptStream()
		if err != nil {
			break
		}
		sig, envOut, err := readFrame(rs)
		if err != nil {
			break
		}
		if !ed25519.Verify(clientPub, envOut, sig[10:]) {
			rs.Close()
			continue
		}
		v, b := envelopeFields(envOut)
		if v[2] == 44 && v[1] == 60 {
			_, sb := envelopeFields(b[3])
			fmt.Printf("ASYNC EXECUTE ok: id=%d stdout=%q\n", v[1], string(sb[2]))
			rs.Close()
			break
		}
		rs.Close()
	}
	if _, exBody, err := rpcCall(sess, serverPriv, serverPub, clientPub, 51, 44, exReq, 44); err != nil {
		log.Printf("execute failed: %v", err)
	} else {
		ev, eb := envelopeFields(exBody[3])
		_, er := envelopeFields(eb[9])
		fmt.Printf("EXECUTE ok: status=%d pid=%d stdout=%q stderr=%q err=%q\n",
			ev[1], ev[4], string(eb[2]), string(eb[3]), string(er[1]))
	}
	_ = os.Remove(tmpFile)

	// Port forward: peer runs a local HTTP server, asks the implant to relay to
	// it through tunnel 0xAABBCCEE, then speaks HTTP over the tunnel.
	echoAddr, stopEcho := startEchoServer()
	_, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort, _ := strconv.Atoi(echoPortStr)
	defer stopEcho()
	pfTunnel := uint64(0xAABBCCEE)
	// Real clients bind a freshly created tunnel with a zero-byte TunnelData
	// before sending PortfwdReq; the implant must acknowledge it.
	bindTd := appendUvarint(nil, 8<<3)
	bindTd = appendUvarint(bindTd, pfTunnel)
	if v, _, err := rawExchange(sess, serverPriv, serverPub, clientPub, makeEnvelope(54, 22, bindTd)); err == nil {
		fmt.Printf("TUNNEL BIND ok: ack=%d tunnel=%d\n", v[4], v[8])
	} else {
		log.Printf("tunnel bind failed: %v", err)
	}
	pfReq := append(protoStr(3, "127.0.0.1"), appendUvarint(nil, 1<<3)...)
	pfReq = appendUvarint(pfReq, uint64(echoPort))
	pfReq = append(pfReq, appendUvarint(nil, 8<<3)...)
	pfReq = appendUvarint(pfReq, pfTunnel)
	if _, pfBody, err := rpcCall(sess, serverPriv, serverPub, clientPub, 55, 80, pfReq, 81); err != nil {
		log.Printf("portfwd failed: %v (echo %s)", err, echoAddr)
	} else {
		_, pf := envelopeFields(pfBody[3])
		fmt.Printf("PORTFWD ok: host=%q port=%d tunnel=%d\n", string(pf[3]), pf[1], pf[8])
		// Send an HTTP request through the tunnel and read the response.
		req := []byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n")
		td := append(protoStrBytes(1, req), appendUvarint(nil, 8<<3)...)
		td = appendUvarint(td, pfTunnel)
		env := makeEnvelope(56, 22, td)
		if st, err := sess.OpenStream(); err == nil {
			_ = writeFrame(st, rawSignature(serverPriv, serverPub, env), env)
		}
		respText := ""
		for i := 0; i < 20 && !strings.Contains(respText, "hello-portfwd") ; i++ {
			rs, err := sess.AcceptStream()
			if err != nil {
				break
			}
			_, envOut, err := readFrame(rs)
			if err != nil {
				break
			}
			v, b := envelopeFields(envOut)
			if v[2] == 22 {
				_, db := envelopeFields(b[3])
				respText += string(db[1])
			}
			rs.Close()
		}
		fmt.Printf("PORTFWD DATA: %q\n", strings.TrimSpace(respText))
	}

	// Server initiated stream with a message type the implant does not implement
	// (MsgType 200): it must answer Envelope{ID, UnknownMessageType:true}.
	unknown := []byte{0x08, 0xb9, 0x60, 0x10, 0xc8, 0x01, 0x1a, 0x01, 0x78}
	if _, resp, err := rawExchange(sess, serverPriv, serverPub, clientPub, unknown); err != nil {
		log.Printf("unknown-type roundtrip failed: %v", err)
	} else {
		v, _ := envelopeFields(resp)
		fmt.Printf("IMPLANT REPLY ok: type=%d id=%d unknown-type=%d\n", v[2], v[1], v[4])
	}
	// Shell: ShellReq(20) -> Shell(21){Pid, TunnelID}, then TunnelData(22) both ways.
	clientTunnel := uint64(0xAABBCCDD)
	shReq := append(protoStr(1, cmdExe), appendUvarint(nil, 8<<3)...)
	shReq = appendUvarint(shReq, clientTunnel)
	if _, shBody, err := rpcCall(sess, serverPriv, serverPub, clientPub, 52, 20, shReq, 21); err != nil {
		log.Printf("shell failed: %v", err)
	} else {
		sv, sb := envelopeFields(shBody[3])
		tunnel := sv[8]
		_, shr := envelopeFields(sb[9])
		fmt.Printf("SHELL ok: pid=%d tunnel=%d (client asked %d) err=%q\n", sv[3], tunnel, clientTunnel, string(shr[1]))
		stdin := append(protoStrBytes(1, []byte("dir C:\\Windows\\System32\r\necho after-big\r\n")), appendUvarint(nil, 8<<3)...)
		stdin = appendUvarint(stdin, tunnel)
		env := makeEnvelope(53, 22, stdin)
		st, err := sess.OpenStream()
		if err == nil {
			_ = writeFrame(st, rawSignature(serverPriv, serverPub, env), env)
		}
		out := ""
		firstSeq := int64(-1)
		var ackSeen uint64
		frames := 0
		for i := 0; i < 600 && !strings.Contains(out, "after-big") ; i++ {
			rs, err := sess.AcceptStream()
			if err != nil {
				break
			}
			_, envOut, err := readFrame(rs)
			if err != nil {
				break
			}
			v, b := envelopeFields(envOut)
			if v[2] == 22 {
				frames++
				tv, db := envelopeFields(b[3])
				if tv[4] != 0 {
					ackSeen = tv[4]
				} else if firstSeq < 0 {
					firstSeq = int64(tv[3])
				} else {
					out += string(db[1])
				}
			}
			rs.Close()
		}
		fmt.Printf("SHELL OUT (first-seq=%d, ack=%d, frames=%d, big-output-ok=%v, chinese-ok=%v, bytes=%d)\n",
			firstSeq, ackSeen, frames, len(out) > 4096,
			strings.Contains(out, "\u4e2d\u6587\u6d4b\u8bd5") || strings.Contains(out, "\xd6\xd0\xce\xc4\xb2\xe2\xca\xd4"), len(out))
		closeEnv := makeEnvelope(54, 23, appendUvarint(appendUvarint(nil, 8<<3), tunnel))
		if cs, cerr := sess.OpenStream(); cerr == nil {
			_ = writeFrame(cs, rawSignature(serverPriv, serverPub, closeEnv), closeEnv)
		}
	}

}






// parseLs decodes Ls{Path=1, Exists=2, Files=3 repeat FileInfo{Name=1,...}}.
func parseLs(body []byte) (string, []string) {
	path := ""
	var files []string
	i := 0
	for i < len(body) {
		key, n := binary.Uvarint(body[i:])
		if n <= 0 {
			break
		}
		i += n
		field, wire := key>>3, key&7
		if wire == 2 {
			l, n2 := binary.Uvarint(body[i:])
			if n2 <= 0 {
				break
			}
			i += n2
			val := body[i : i+int(l)]
			i += int(l)
			if field == 1 {
				path = string(val)
			}
			if field == 3 {
				// FileInfo: first length-delimited field (1) is the name.
				_, fb := envelopeFields(val)
				files = append(files, string(fb[1]))
			}
		} else if wire == 0 {
			_, n2 := binary.Uvarint(body[i:])
			if n2 <= 0 {
				break
			}
			i += n2
		} else {
			break
		}
	}
	return path, files
}

func firstN(values []string, n int) []string {
	if len(values) < n {
		return values
	}
	return values[:n]
}





// rpcCall performs one request/response exchange the way the Sliver server does:
// request on a new stream, response on a new stream, same envelope id.
func rpcCall(sess *yamux.Session, priv ed25519.PrivateKey, pub, clientPub ed25519.PublicKey,
	id uint64, reqType uint32, payload []byte, wantType uint32) (map[uint64]uint64, map[uint64][]byte, error) {
	env := []byte{0x08}
	env = appendUvarint(env, id)
	env = append(env, 0x10)
	env = appendUvarint(env, uint64(reqType))
	if payload != nil {
		env = append(env, 0x1a)
		env = appendUvarint(env, uint64(len(payload)))
		env = append(env, payload...)
	}
	stream, err := sess.OpenStream()
	if err != nil {
		return nil, nil, err
	}
	if err := writeFrame(stream, rawSignature(priv, pub, env), env); err != nil {
		return nil, nil, err
	}
	respStream, err := sess.AcceptStream()
	if err != nil {
		return nil, nil, err
	}
	sig, resp, err := readFrame(respStream)
	if err != nil {
		return nil, nil, err
	}
	if !ed25519.Verify(clientPub, resp, sig[10:]) {
		return nil, nil, fmt.Errorf("bad response signature")
	}
	v, b := envelopeFields(resp)
	if v[2] != uint64(wantType) {
		return v, b, fmt.Errorf("want type %d got %d", wantType, v[2])
	}
	if v[1] != id {
		return v, b, fmt.Errorf("response id %d != %d", v[1], id)
	}
	stream.Close()
	respStream.Close()
	return v, b, nil
}

func appendUvarint(dst []byte, v uint64) []byte {
	var buf [10]byte
	n := binary.PutUvarint(buf[:], v)
	return append(dst, buf[:n]...)
}

// protoStr encodes a length-delimited field with a string payload.
func protoStr(field uint64, s string) []byte {
	out := appendUvarint(nil, field<<3|2)
	out = appendUvarint(out, uint64(len(s)))
	return append(out, s...)
}


// countRepeated counts repeated length-delimited fields in a message body.
func countRepeated(body []byte) int {
	count := 0
	i := 0
	for i < len(body) {
		key, n := binary.Uvarint(body[i:])
		if n <= 0 {
			break
		}
		i += n
		wire := key & 7
		field := key >> 3
		switch wire {
		case 2:
			l, n2 := binary.Uvarint(body[i:])
			if n2 <= 0 {
				return count
			}
			i += n2 + int(l)
			if field == 1 || field == 3 {
				count++
			}
		case 0:
			_, n2 := binary.Uvarint(body[i:])
			if n2 <= 0 {
				return count
			}
			i += n2
		default:
			return count
		}
	}
	return count
}



// rawExchange sends a pre-built envelope and returns the (signed) response.
func rawExchange(sess *yamux.Session, priv ed25519.PrivateKey, pub, clientPub ed25519.PublicKey,
	env []byte) (map[uint64]uint64, []byte, error) {
	stream, err := sess.OpenStream()
	if err != nil {
		return nil, nil, err
	}
	if err := writeFrame(stream, rawSignature(priv, pub, env), env); err != nil {
		return nil, nil, err
	}
	respStream, err := sess.AcceptStream()
	if err != nil {
		return nil, nil, err
	}
	sig, resp, err := readFrame(respStream)
	if err != nil {
		return nil, nil, err
	}
	if !ed25519.Verify(clientPub, resp, sig[10:]) {
		return nil, nil, fmt.Errorf("bad response signature")
	}
	v, _ := envelopeFields(resp)
	stream.Close()
	respStream.Close()
	return v, resp, nil
}



func protoStrBytes(field uint64, data []byte) []byte {
	out := appendUvarint(nil, field<<3|2)
	out = appendUvarint(out, uint64(len(data)))
	return append(out, data...)
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return fi.Size()
}

func firstByte(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	return int(b[0])
}





func makeEnvelope(id, typ uint64, payload []byte) []byte {
	env := appendUvarint(nil, 1<<3)
	env = appendUvarint(env, id)
	env = append(env, 0x10)
	env = appendUvarint(env, typ)
	if payload != nil {
		env = append(env, 0x1a)
		env = appendUvarint(env, uint64(len(payload)))
		env = append(env, payload...)
	}
	return env
}

















// startEchoServer runs a tiny HTTP server and returns its address + a stopper.
func startEchoServer() (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.0 200 OK\r\nContent-Length: 13\r\n\r\nhello-portfwd"))
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}







