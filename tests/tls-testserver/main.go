// Command tls-testserver is a throw-away TLS 1.3 mTLS echo server used to
// exercise the C implant's handshake path (--tls-selftest).
//
// It generates a private CA, a server certificate and a client certificate,
// writes them as PEM into the output directory, then listens with:
//   - TLS 1.3 only
//   - client certificates required and verified against the same CA
//
// Usage:
//   go run ./tests/tls-testserver -addr 127.0.0.1:9443 -out ./build/tls-fixtures
//
// The printed files map straight onto:
//   implant.exe --tls-selftest 127.0.0.1 9443 <out>/ca.pem <out>/client.pem <out>/client.key
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type fixture struct {
	certPEM []byte
	keyPEM  []byte
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, key, &fixture{certPEM: certPEM, cert: cert, key: key}, nil
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
	}
	if usage == x509.ExtKeyUsageServerAuth {
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
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

func write(outDir, name string, data []byte) error {
	return os.WriteFile(filepath.Join(outDir, name), data, 0o600)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:9443", "listen address")
	outDir := flag.String("out", "build/tls-fixtures", "directory for the PEM fixtures")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		log.Fatalf("mkdir %s: %v", *outDir, err)
	}

	caCert, caKey, ca, err := newCA()
	if err != nil {
		log.Fatalf("ca: %v", err)
	}
	server, err := issue(caCert, caKey, "sliver-cpp test server", x509.ExtKeyUsageServerAuth)
	if err != nil {
		log.Fatalf("server cert: %v", err)
	}
	client, err := issue(caCert, caKey, "sliver-cpp test client", x509.ExtKeyUsageClientAuth)
	if err != nil {
		log.Fatalf("client cert: %v", err)
	}

	for name, data := range map[string][]byte{
		"ca.pem":     ca.certPEM,
		"server.pem": server.certPEM,
		"server.key": server.keyPEM,
		"client.pem": client.certPEM,
		"client.key": client.keyPEM,
	} {
		if err := write(*outDir, name, data); err != nil {
			log.Fatalf("write %s: %v", name, err)
		}
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	tlsCert := tls.Certificate{
		Certificate: [][]byte{server.cert.Raw},
		PrivateKey:  server.key,
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}

	ln, err := tls.Listen("tcp", *addr, cfg)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	fmt.Printf("listening on %s (TLS 1.3, mTLS required)\n", *addr)
	fmt.Printf("fixtures in %s\n", *outDir)
	fmt.Printf("  implant.exe --tls-selftest %s %s %s %s %s\n",
		hostOf(*addr), portOf(*addr),
		filepath.Join(*outDir, "ca.pem"),
		filepath.Join(*outDir, "client.pem"),
		filepath.Join(*outDir, "client.key"))

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	state := conn.(*tls.Conn)
	if err := state.Handshake(); err != nil {
		log.Printf("handshake error: %v", err)
		return
	}
	cs := state.ConnectionState()
	log.Printf("handshake ok: version=%s cipher=%s client-cert=%s",
		tls.VersionName(cs.Version), tls.CipherSuiteName(cs.CipherSuite),
		cs.PeerCertificates[0].Subject.CommonName)

	// The implant writes "MUX/1" first, then a probe line; echo everything back.
	reader := bufio.NewReader(conn)
	buf := make([]byte, 512)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func hostOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "9443"
	}
	return port
}
