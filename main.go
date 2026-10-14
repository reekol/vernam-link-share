package main

import (
	"embed"
	"io/fs"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)


//go:embed web
var embeddedWeb embed.FS

const maxMessageBytes = 1 << 20 // 1 MiB

type Message struct {
	Ciphertext string    `json:"ciphertext"`
	CreatedAt  time.Time `json:"createdAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

type Store struct {
	mu       sync.Mutex
	messages map[string]Message
}

func NewStore() *Store { return &Store{messages: make(map[string]Message)} }

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil { return nil, err }
	return b, nil
}

func randomID() (string, error) {
	b, err := randomBytes(24)
	if err != nil { return "", err }
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Vernam/XOR one-time pad: key must be cryptographically random, as long as
// the plaintext, used once, and kept secret. Never reuse a key.
func xorOTP(plain, key []byte) []byte {
	out := make([]byte, len(plain))
	for i := range plain { out[i] = plain[i] ^ key[i] }
	return out
}

func (s *Store) put(id string, msg Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages[id] = msg
}

func (s *Store) take(id string) (Message, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	msg, ok := s.messages[id]
	if !ok { return Message{}, false }
	delete(s.messages, id) // atomic consume: only one request can get it
	if time.Now().After(msg.ExpiresAt) { return Message{}, false }
	return msg, true
}

func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for id, msg := range s.messages {
			if now.After(msg.ExpiresAt) { delete(s.messages, id) }
		}
		s.mu.Unlock()
	}
}

type Server struct {
	store *Store
	ttl   time.Duration
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxMessageBytes+4096)
	defer r.Body.Close()
	var input struct { Message string `json:"message"` }
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error":"expected JSON body with a message"})
		return
	}
	if strings.TrimSpace(input.Message) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error":"message must not be empty"})
		return
	}
	plain := []byte(input.Message)
	if len(plain) > maxMessageBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error":"message exceeds 1 MiB"})
		return
	}
	key, err := randomBytes(len(plain))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error":"secure random generation failed"})
		return
	}
	ciphertext := xorOTP(plain, key)
	id, err := randomID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error":"secure ID generation failed"})
		return
	}
	s.store.put(id, Message{
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(s.ttl).UTC(),
	})
	// The key is only returned to the sender and should be shared via URL fragment.
	writeJSON(w, http.StatusCreated, map[string]string{
		"id": id,
		"key": base64.RawURLEncoding.EncodeToString(key),
		"expiresIn": s.ttl.String(),
	})
}

func (s *Server) consume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/messages/")
	if id == "" || strings.Contains(id, "/") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error":"invalid message ID"})
		return
	}
	msg, ok := s.store.take(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error":"message not found, expired, or already read"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"ciphertext": msg.Ciphertext,
		"createdAt": msg.CreatedAt.Format(time.RFC3339),
		"expiresAt": msg.ExpiresAt.Format(time.RFC3339),
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
	writeJSON(w, http.StatusOK, map[string]string{"status":"ok"})
}

func main() {
	addr := os.Getenv("ADDR")
	if addr == "" { addr = ":8080" }
	ttl := 24 * time.Hour
	if raw := os.Getenv("MESSAGE_TTL"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 { log.Fatal("MESSAGE_TTL must be a positive Go duration, e.g. 24h") }
		ttl = parsed
	}
	store := NewStore()
	go store.cleanupLoop()
	srv := &Server{store: store, ttl: ttl}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/messages", srv.create)
	mux.HandleFunc("/api/messages/", srv.consume)
	mux.HandleFunc("/healthz", srv.health)
	webFS, err := fs.Sub(embeddedWeb, "web")
	if err != nil {
		log.Fatalf("load embedded web assets: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(webFS)))

	server := &http.Server{
		Addr: addr, Handler: securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout: 60 * time.Second,
	}
	log.Printf("Vernam Share listening on %s (message TTL %s)", addr, ttl)
	log.Fatal(server.ListenAndServe())
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// Retained as a small helper for future key fingerprint diagnostics; never log keys.
func keyFingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}

var _ = errors.New
var _ = fmt.Sprintf
var _ io.Reader
