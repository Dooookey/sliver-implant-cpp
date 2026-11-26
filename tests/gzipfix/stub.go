package main

// stub.go - offline stand-in for a Sliver HTTP C2 listener (regression only).
//
//   POST, no cookie : HTTPSessionInit (age key exchange) -> 200 + Set-Cookie,
//                     body = CipherCtx.Encrypt(session id)
//   POST, cookie    : CipherCtx.Decrypt(envelope) -> 202
//   GET,  cookie    : 200 with [74B header][CipherCtx.Encrypt(envelope)] or 204
//
// Configuration comes from the environment so the PowerShell harness can drive it
// without flag plumbing:
//   STUB_ADDR       listen address (default 127.0.0.1:9780)
//   STUB_SERVER_ID  age identity of the "server" (AGE-SECRET-KEY-1...)
//   STUB_PEER_ID    age identity of the "implant" (for the HMAC check)
//   STUB_COOKIE     cookie name (default "sid")
//   STUB_TASK       optional hex-encoded envelope to hand out on the first poll

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
)

type stubSession struct {
	key []byte
	id  string
}

type stubState struct {
	mu       sync.Mutex
	sessions map[string]*stubSession
	serverID age.Identity
	peerID   string
	cookie   string
	queued   [][]byte
	sawPost  int
}

func stubEncrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	var gz bytes.Buffer
	w, err := gzip.NewWriterLevel(&gz, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+gz.Len()+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, gz.Bytes(), nil), nil
}

func stubDecrypt(key, ct []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
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

// stubInitKey extracts HTTPSessionInit.Key (field 1, length delimited).
func stubInitKey(msg []byte) ([]byte, error) {
	if len(msg) < 2 || msg[0] != 0x0a {
		return nil, fmt.Errorf("unexpected tag")
	}
	var l uint64
	var shift uint
	i := 1
	for ; i < len(msg); i++ {
		l |= uint64(msg[i]&0x7f) << shift
		if msg[i] < 0x80 {
			i++
			break
		}
		shift += 7
	}
	if int(l)+i > len(msg) || l != 32 {
		return nil, fmt.Errorf("bad key length %d", l)
	}
	return msg[i : i+int(l)], nil
}

func (s *stubState) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))

	var sess *stubSession
	if c, err := r.Cookie(s.cookie); err == nil {
		s.mu.Lock()
		sess = s.sessions[c.Value]
		s.mu.Unlock()
	}

	if sess == nil {
		if r.Method != http.MethodPost || len(body) < 40 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		dec, err := age.Decrypt(bytes.NewReader(append([]byte(ageMsgPrefix), body[32:]...)), s.serverID)
		if err != nil {
			fmt.Printf("STUB SESSION fail: age %v\n", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		plaintext, err := io.ReadAll(dec)
		if err != nil || len(plaintext) < 33 {
			fmt.Printf("STUB SESSION fail: short plaintext\n")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		digest := sha256.Sum256([]byte(s.peerID))
		mac := hmac.New(sha256.New, digest[:])
		mac.Write(plaintext[32:])
		if !hmac.Equal(mac.Sum(nil), plaintext[:32]) {
			fmt.Printf("STUB SESSION fail: hmac\n")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		key, err := stubInitKey(plaintext[32:])
		if err != nil {
			fmt.Printf("STUB SESSION fail: init %v\n", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		idRaw := make([]byte, 16)
		if _, err := rand.Read(idRaw); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		id := hex.EncodeToString(idRaw)
		s.mu.Lock()
		s.sessions[id] = &stubSession{key: append([]byte(nil), key...), id: id}
		if task := os.Getenv("STUB_TASK"); task != "" && len(s.queued) == 0 {
			if raw, err := hex.DecodeString(task); err == nil {
				s.queued = append(s.queued, raw)
			}
		}
		s.mu.Unlock()

		resp, err := stubEncrypt(key, []byte(id))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: s.cookie, Value: id, Path: "/"})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
		fmt.Printf("STUB SESSION ok: %s\n", id)
		return
	}

	switch r.Method {
	case http.MethodPost:
		plaintext, err := stubDecrypt(sess.key, body)
		if err != nil {
			fmt.Printf("STUB POST fail: decrypt %v\n", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		s.mu.Lock()
		s.sawPost++
		s.mu.Unlock()
		fmt.Printf("STUB POST ok: %d bytes\n", len(plaintext))
		w.WriteHeader(http.StatusAccepted)
	case http.MethodGet:
		s.mu.Lock()
		var task []byte
		if len(s.queued) > 0 {
			task = s.queued[0]
			s.queued = s.queued[1:]
		}
		s.mu.Unlock()
		if task == nil {
			// Emulate the listener's long poll: hold the request until a task shows
			// up or the deadline passes.
			deadline := time.Now().Add(stubPollTimeout())
			for task == nil && time.Now().Before(deadline) {
				time.Sleep(50 * time.Millisecond)
				s.mu.Lock()
				if len(s.queued) > 0 {
					task = s.queued[0]
					s.queued = s.queued[1:]
				}
				s.mu.Unlock()
			}
			if task == nil {
				w.WriteHeader(http.StatusNoContent)
				fmt.Printf("STUB POLL idle\n")
				return
			}
		}
		ct, err := stubEncrypt(sess.key, task)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		header := make([]byte, 74) // mirrors the listener's minisign prefix
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(header)
		_, _ = w.Write(ct)
		fmt.Printf("STUB POLL ok: %d bytes\n", len(task))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func stubPollTimeout() time.Duration {
	ms := 5000
	if v := os.Getenv("STUB_POLL_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ms = n
		}
	}
	return time.Duration(ms) * time.Millisecond
}

func runStub() {
	addr := os.Getenv("STUB_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9780"
	}
	serverIDText := os.Getenv("STUB_SERVER_ID")
	peerID := os.Getenv("STUB_PEER_ID")
	if serverIDText == "" || peerID == "" {
		fmt.Println("stub: STUB_SERVER_ID and STUB_PEER_ID are required")
		os.Exit(2)
	}
	identity, err := age.ParseX25519Identity(serverIDText)
	if err != nil {
		fmt.Println("stub: bad server identity:", err)
		os.Exit(2)
	}
	cookie := os.Getenv("STUB_COOKIE")
	if cookie == "" {
		cookie = "sid"
	}
	state := &stubState{
		sessions: map[string]*stubSession{},
		serverID: identity,
		peerID:   peerID,
		cookie:   cookie,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", state.handle)
	fmt.Printf("STUB listening on %s (cookie %s)\n", addr, cookie)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Println("stub:", err)
		os.Exit(1)
	}
}
