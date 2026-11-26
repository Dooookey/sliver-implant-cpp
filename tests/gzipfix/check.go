package main

// Fixtures and cross-language checks for the C runtime.
//
//   gen        gzip fixtures (Go compress/gzip BestSpeed)  -> fixture-<n>.{gz,raw}
//   check      verify C's gzip output                      -> ours-<n>.gz
//   cipher-gen CipherContext fixtures (chacha20poly1305)   -> cipher-<n>.{bin,raw}
//   keyex-gen  age key exchange fixtures                   -> keyex-*.{id,pub,raw}
//   keyex-check verify C's AgeKeyExToServer message        -> ours-keyex-<n>.bin

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
)

const ageMsgPrefix = "age-encryption.org/v1\n-> X25519 "

var payloads = map[string][]byte{
	"c1": []byte("hello ciphercontext\n"),
	"c2": bytes.Repeat([]byte("XY"), 700),
	"c3": []byte("中文 payload 测试 cipher"),
}

var keyexPayloads = map[string][]byte{
	"k1": []byte("session-init-key-32-bytes-here!!"),
	"k2": bytes.Repeat([]byte{0x42}, 4000),
	"k3": []byte("中文 session init 数据"),
}

func must(err error) {
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
}

func dir() string {
	d := filepath.Join("..", "..", "build")
	must(os.MkdirAll(d, 0o755))
	return d
}

func encrypt(key [32]byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	var gz bytes.Buffer
	w, _ := gzip.NewWriterLevel(&gz, gzip.BestSpeed)
	w.Write(plaintext)
	w.Close()
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+gz.Len()+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, gz.Bytes(), nil), nil
}

func decrypt(key [32]byte, ct []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	if len(ct) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	plaintext, err := aead.Open(nil, ct[:aead.NonceSize()], ct[aead.NonceSize():], nil)
	if err != nil {
		return nil, err
	}
	r, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func fixedKey() [32]byte {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func keyexGen(d string) {
	server, err := age.GenerateX25519Identity()
	must(err)
	peer, err := age.GenerateX25519Identity()
	must(err)
	must(os.WriteFile(filepath.Join(d, "keyex-server.id"), []byte(server.String()), 0o600))
	must(os.WriteFile(filepath.Join(d, "keyex-server.pub"), []byte(server.Recipient().String()), 0o644))
	must(os.WriteFile(filepath.Join(d, "keyex-peer.id"), []byte(peer.String()), 0o600))
	must(os.WriteFile(filepath.Join(d, "keyex-peer.pub"), []byte(peer.Recipient().String()), 0o644))
	for name, p := range keyexPayloads {
		must(os.WriteFile(filepath.Join(d, "keyex-"+name+".raw"), p, 0o644))
	}
	fmt.Printf("keyex fixtures: server=%s peer=%s\n", server.Recipient().String()[:12]+"...",
		peer.Recipient().String()[:12]+"...")
}

// keyexCheck verifies a message produced by sliver_age_keyex_to_server:
// SHA256(peer.public) || age_encrypt(server.public, HMAC || plaintext).
func keyexCheck(d string) int {
	serverIDText, err := os.ReadFile(filepath.Join(d, "keyex-server.id"))
	if err != nil {
		fmt.Println("SKIP keyex: fixtures missing")
		return 0
	}
	peerIDText, err := os.ReadFile(filepath.Join(d, "keyex-peer.id"))
	must(err)
	peerPub, err := os.ReadFile(filepath.Join(d, "keyex-peer.pub"))
	must(err)

	serverID, err := age.ParseX25519Identity(string(serverIDText))
	must(err)

	fail := 0
	for name, want := range keyexPayloads {
		msg, err := os.ReadFile(filepath.Join(d, "ours-keyex-"+name+".bin"))
		if err != nil {
			fmt.Printf("SKIP keyex %s: %v\n", name, err)
			continue
		}
		if len(msg) < 32+32 {
			fmt.Printf("FAIL keyex %s: message too short (%d)\n", name, len(msg))
			fail++
			continue
		}
		pubDigest := sha256.Sum256(peerPub)
		if !hmac.Equal(msg[:32], pubDigest[:]) {
			fmt.Printf("FAIL keyex %s: public-key prefix mismatch\n", name)
			fail++
			continue
		}
		body := append([]byte(ageMsgPrefix), msg[32:]...)
		r, err := age.Decrypt(bytes.NewReader(body), serverID)
		if err != nil {
			fmt.Printf("FAIL keyex %s: age decrypt: %v\n", name, err)
			fail++
			continue
		}
		plaintext, err := io.ReadAll(r)
		if err != nil {
			fmt.Printf("FAIL keyex %s: read: %v\n", name, err)
			fail++
			continue
		}
		if len(plaintext) < 32 {
			fmt.Printf("FAIL keyex %s: plaintext too short\n", name)
			fail++
			continue
		}
		privateDigest := sha256.Sum256(peerIDText)
		mac := hmac.New(sha256.New, privateDigest[:])
		mac.Write(plaintext[32:])
		if !hmac.Equal(mac.Sum(nil), plaintext[:32]) {
			fmt.Printf("FAIL keyex %s: HMAC mismatch\n", name)
			fail++
			continue
		}
		if !bytes.Equal(plaintext[32:], want) {
			fmt.Printf("FAIL keyex %s: payload mismatch (%d vs %d)\n", name,
				len(plaintext[32:]), len(want))
			fail++
			continue
		}
		fmt.Printf("OK keyex %s: %d bytes verified\n", name, len(want))
	}
	return fail
}

func main() {
	mode := "gen"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	d := dir()
	fail := 0

	switch mode {
	case "gen":
		for name, p := range map[string][]byte{
			"s1": []byte("hello sliver http c2\n"),
			"s2": bytes.Repeat([]byte("abc123"), 500),
			"s3": bytes.Repeat([]byte{0}, 4000),
			"s4": []byte("chinese-payload: 中文测试 payload 数据"),
		} {
			var b bytes.Buffer
			w, _ := gzip.NewWriterLevel(&b, gzip.BestSpeed)
			w.Write(p)
			w.Close()
			must(os.WriteFile(filepath.Join(d, "fixture-"+name+".gz"), b.Bytes(), 0o644))
			must(os.WriteFile(filepath.Join(d, "fixture-"+name+".raw"), p, 0o644))
		}
		fmt.Println("gzip fixtures written")
	case "check":
		for name := range map[string][]byte{"s1": nil, "s2": nil, "s3": nil, "s4": nil} {
			gzData, err := os.ReadFile(filepath.Join(d, "ours-"+name+".gz"))
			if err != nil {
				fmt.Printf("SKIP %s: %v\n", name, err)
				continue
			}
			want, err := os.ReadFile(filepath.Join(d, "fixture-"+name+".raw"))
			must(err)
			r, err := gzip.NewReader(bytes.NewReader(gzData))
			if err != nil {
				fmt.Printf("FAIL %s: %v\n", name, err)
				fail++
				continue
			}
			got, err := io.ReadAll(r)
			must(err)
			if !bytes.Equal(got, want) {
				fmt.Printf("FAIL %s: mismatch\n", name)
				fail++
				continue
			}
			fmt.Printf("OK %s: %d bytes\n", name, len(got))
		}
	case "cipher-gen":
		key := fixedKey()
		for name, p := range payloads {
			ct, err := encrypt(key, p)
			must(err)
			must(os.WriteFile(filepath.Join(d, "cipher-"+name+".bin"), ct, 0o644))
			must(os.WriteFile(filepath.Join(d, "cipher-"+name+".raw"), p, 0o644))
			fmt.Printf("gen %s ct=%d raw=%d\n", name, len(ct), len(p))
		}
	case "cipher-check":
		key := fixedKey()
		for name, p := range payloads {
			ct, err := os.ReadFile(filepath.Join(d, "ours-cipher-"+name+".bin"))
			if err != nil {
				fmt.Printf("SKIP %s: %v\n", name, err)
				continue
			}
			got, err := decrypt(key, ct)
			if err != nil {
				fmt.Printf("FAIL %s: %v\n", name, err)
				fail++
				continue
			}
			if !bytes.Equal(got, p) {
				fmt.Printf("FAIL %s: mismatch\n", name)
				fail++
				continue
			}
			fmt.Printf("OK %s: %d bytes\n", name, len(got))
		}
	case "keyex-gen":
		keyexGen(d)
	case "stub":
		runStub()
		fail = keyexCheck(d)
	default:
		fmt.Println("unknown mode:", mode)
		os.Exit(2)
	}

	if fail != 0 {
		fmt.Printf("%s: %d failure(s)\n", mode, fail)
		os.Exit(1)
	}
	fmt.Printf("%s: PASS\n", mode)
}
