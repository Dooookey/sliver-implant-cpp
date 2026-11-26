package main

// Cross-language fixtures for the CipherContext frame:
//  - gen   : Go encrypts payloads with a fixed key -> build/cipher-<n>.bin
//  - check : Go decrypts build/ours-cipher-<n>.bin and compares with the payload

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"
)

var payloads = map[string][]byte{
	"c1": []byte("hello ciphercontext\n"),
	"c2": bytes.Repeat([]byte("XY"), 700),
	"c3": []byte("中文 payload 测试 cipher"),
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

func main() {
	mode := "gen"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	dir := filepath.Join("..", "..", "build")
	os.MkdirAll(dir, 0o755)
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	fail := 0
	for name, payload := range payloads {
		if mode == "gen" {
			ct, err := encrypt(key, payload)
			if err != nil {
				fmt.Println("encrypt:", err)
				os.Exit(1)
			}
			os.WriteFile(filepath.Join(dir, "cipher-"+name+".bin"), ct, 0o644)
			os.WriteFile(filepath.Join(dir, "cipher-"+name+".raw"), payload, 0o644)
			fmt.Printf("gen %s ct=%d raw=%d\n", name, len(ct), len(payload))
			continue
		}
		ct, err := os.ReadFile(filepath.Join(dir, "ours-cipher-"+name+".bin"))
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
		if !bytes.Equal(got, payload) {
			fmt.Printf("FAIL %s: mismatch (%d vs %d bytes)\n", name, len(got), len(payload))
			fail++
			continue
		}
		fmt.Printf("OK %s: %d bytes\n", name, len(got))
	}
	if fail != 0 {
		fmt.Printf("cipher check: %d failure(s)\n", fail)
		os.Exit(1)
	}
	fmt.Println("cipher check: PASS")
}
