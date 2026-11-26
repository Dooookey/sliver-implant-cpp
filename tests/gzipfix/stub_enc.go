package main

// stub_enc.go - encoder support for the listener stub.
//
// The real listener derives the codec from the URL nonce
// (EncoderFromNonce: id = nonce % 65537, 0 = passthrough) and the implant must use
// the same one. The stub mirrors that, with the id -> codec table taken from
// STUB_ENC_MAP (e.g. "101:base64,104:hex"), so the same build configuration can
// drive every codec.

import (
	"bytes"
	"compress/gzip"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

type stubCodec interface {
	Name() string
	Encode([]byte) ([]byte, error)
	Decode([]byte) ([]byte, error)
}

type nopCodec struct{}

func (nopCodec) Name() string                    { return "nop" }
func (nopCodec) Encode(b []byte) ([]byte, error) { return b, nil }
func (nopCodec) Decode(b []byte) ([]byte, error) { return b, nil }

type b64Codec struct{ enc *base64.Encoding }

func (c b64Codec) Name() string                    { return "base64" }
func (c b64Codec) Encode(b []byte) ([]byte, error) { return []byte(c.enc.EncodeToString(b)), nil }
func (c b64Codec) Decode(b []byte) ([]byte, error) { return c.enc.DecodeString(string(b)) }

type b32Codec struct{ enc *base32.Encoding }

func (c b32Codec) Name() string                    { return "base32" }
func (c b32Codec) Encode(b []byte) ([]byte, error) { return []byte(c.enc.EncodeToString(b)), nil }
func (c b32Codec) Decode(b []byte) ([]byte, error) { return c.enc.DecodeString(string(b)) }

type hexCodec struct{}

func (hexCodec) Name() string                    { return "hex" }
func (hexCodec) Encode(b []byte) ([]byte, error) { return []byte(hex.EncodeToString(b)), nil }
func (hexCodec) Decode(b []byte) ([]byte, error) { return hex.DecodeString(string(b)) }

type gzipCodec struct{}

func (gzipCodec) Name() string { return "gzip" }
func (gzipCodec) Encode(b []byte) ([]byte, error) {
	var out bytes.Buffer
	w, err := gzip.NewWriterLevel(&out, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func (gzipCodec) Decode(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// Sliver's custom alphabets (util/encoders), no padding.
const (
	stubBase64Alphabet = "a0b2c5def6hijklmnopqr_st-uvwxyzA1B3C4DEFGHIJKLM7NO9PQR8ST+UVWXYZ"
	stubBase32Alphabet = "ab1c2d3e4f5g6h7j8k9m0npqrtuvwxyz"
)

func stubBuiltinCodec(name string) stubCodec {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "base64":
		return b64Codec{enc: base64.NewEncoding(stubBase64Alphabet).WithPadding(base64.NoPadding)}
	case "base32":
		return b32Codec{enc: base32.NewEncoding(stubBase32Alphabet).WithPadding(base32.NoPadding)}
	case "hex":
		return hexCodec{}
	case "gzip":
		return gzipCodec{}
	default:
		return nopCodec{}
	}
}

// stubEncoderMap parses STUB_ENC_MAP ("101:base64,104:hex").
func stubEncoderMap() map[uint64]stubCodec {
	out := map[uint64]stubCodec{}
	for _, pair := range strings.Split(os.Getenv("STUB_ENC_MAP"), ",") {
		parts := strings.Split(strings.TrimSpace(pair), ":")
		if len(parts) != 2 {
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 64)
		if err != nil {
			continue
		}
		out[id] = stubBuiltinCodec(parts[1])
	}
	return out
}

// stubCodecFor mirrors EncoderFromNonce: the first query value that yields digits
// is the nonce; the codec is nonce % 65537 mapped through STUB_ENC_MAP.
func stubCodecFor(r *http.Request) stubCodec {
	m := stubEncoderMap()
	for _, values := range r.URL.Query() {
		if len(values) == 0 {
			continue
		}
		digits := digitsOnly(values[0])
		if digits == "" {
			continue
		}
		nonce, err := strconv.ParseUint(digits, 10, 64)
		if err != nil {
			continue
		}
		id := nonce % 65537
		if id == 0 {
			return nopCodec{}
		}
		if codec, ok := m[id]; ok {
			return codec
		}
		fmt.Printf("STUB ENCODER unknown id %d\n", id)
		return nopCodec{}
	}
	return nopCodec{}
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// keep chacha20poly1305 referenced so gofmt/vet do not drop the import in future edits
var _ = chacha20poly1305.New
