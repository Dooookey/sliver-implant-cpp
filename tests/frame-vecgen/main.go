// Command frame-vecgen prints Ed25519 vectors for the C frame-layer tests.
//
// It mirrors the derivation in src/wire/frame.c:
//
//	seed = SHA256("env-signing-v1:" + agePrivateKeyString)
//	pub  = Ed25519(seed).public
//	sig  = Ed25519(seed).sign(message)
//
// Usage:
//
//	go run . "AGE-SECRET-KEY-1..." [message]
//
// The printed hex strings are pasted into tests/unit/test_wire.c.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, `usage: frame-vecgen "AGE-SECRET-KEY-1..." [message]`)
		os.Exit(2)
	}
	agePrivate := os.Args[1]
	msg := "sliver-frame-test"
	if len(os.Args) > 2 {
		msg = os.Args[2]
	}

	digest := sha256.Sum256([]byte("env-signing-v1:" + agePrivate))
	priv := ed25519.NewKeyFromSeed(digest[:])
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, []byte(msg))

	fmt.Printf("seed-sha256 = %s\n", hex.EncodeToString(digest[:]))
	fmt.Printf("public-key  = %s\n", hex.EncodeToString(pub))
	fmt.Printf("message     = %s\n", msg)
	fmt.Printf("signature   = %s\n", hex.EncodeToString(sig))
}
