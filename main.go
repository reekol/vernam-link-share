package main

import (
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web
var embeddedWeb embed.FS

const maxMessageBytes = 1 << 20 // 1 MiB

type Message struct {
	Cipherx   string    `json:"cipherx"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	MaxViews  int       `json:"maxViews"`
	ViewsUsed int       `json:"viewsUsed"`
}

type Store struct {
	mu       sync.Mutex
	messages map[string]Message
	limit    int
}

// NewStore creates an in-memory store. If no limit is supplied, it defaults
// to 1000 messages. A non-positive limit is normalized to the default.
func NewStore(limits ...int) *Store {
	limit := 1000
	if len(limits) > 0 && limits[0] > 0 {
		limit = limits[0]
	}
	return &Store{messages: make(map[string]Message), limit: limit}
}

func (s *Store) removeExpiredLocked(now time.Time) {
	for id, msg := range s.messages {
		if now.After(msg.ExpiresAt) {
			delete(s.messages, id)
		}
	}
}

// put stores a message only if capacity is available.
func (s *Store) put(id string, msg Message) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeExpiredLocked(time.Now())
	if _, exists := s.messages[id]; !exists && len(s.messages) >= s.limit {
		return false
	}
	s.messages[id] = msg
	return true
}

// stats returns the active message count and configured capacity.
func (s *Store) stats() (used, limit int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeExpiredLocked(time.Now())
	return len(s.messages), s.limit
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func randomID() (string, error) {
	b, err := randomBytes(24)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Vernam/XOR one-time pad: key must be cryptographically random, as long as
// the plaintext, used once, and kept secret. Never reuse a key.
func xorOTP(plain, key []byte) []byte {
	out := make([]byte, len(plain))
	for i := range plain {
		out[i] = plain[i] ^ key[i]
	}
	return out
}

// view atomically records one successful retrieval. The message is deleted
// as soon as its configured view limit is reached.
func (s *Store) view(id string) (Message, int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	msg, ok := s.messages[id]
	if !ok {
		return Message{}, 0, false
	}
	if time.Now().After(msg.ExpiresAt) {
		delete(s.messages, id)
		return Message{}, 0, false
	}
	if msg.ViewsUsed >= msg.MaxViews {
		delete(s.messages, id)
		return Message{}, 0, false
	}
	msg.ViewsUsed++
	remaining := msg.MaxViews - msg.ViewsUsed
	if remaining == 0 {
		delete(s.messages, id)
	} else {
		s.messages[id] = msg
	}
	return msg, remaining, true
}

func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for id, msg := range s.messages {
			if now.After(msg.ExpiresAt) {
				delete(s.messages, id)
			}
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
	var input struct {
		Message  string `json:"message"`
		MaxViews *int   `json:"maxViews"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected JSON body with a message"})
		return
	}
	if strings.TrimSpace(input.Message) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message must not be empty"})
		return
	}
	maxViews := 1
	if input.MaxViews != nil {
		maxViews = *input.MaxViews
	}
	if maxViews < 1 || maxViews > 1000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "maxViews must be between 1 and 1000"})
		return
	}
	plain := []byte(input.Message)
	if len(plain) > maxMessageBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "message exceeds 1 MiB"})
		return
	}
	key, err := randomBytes(len(plain))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "secure random generation failed"})
		return
	}
	cipherx := xorOTP(plain, key)
	id, err := randomID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "secure ID generation failed"})
		return
	}
	if !s.store.put(id, Message{
		Cipherx:   base64.RawURLEncoding.EncodeToString(cipherx),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(s.ttl).UTC(),
		MaxViews:  maxViews,
	}) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "message store is full; try again later"})
		return
	}
	// The key is only returned to the sender and should be shared via URL fragment.
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":             id,
		"key":            base64.RawURLEncoding.EncodeToString(key),
		"expiresIn":      s.ttl.String(),
		"maxViews":       maxViews,
		"viewsUsed":      0,
		"viewsRemaining": maxViews,
	})
}

// createCipherx stores cipherx generated by a client. The server never
// receives the plaintext or one-time key on this endpoint.
func (s *Server) createCipherx(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Base64url expands a 1 MiB cipherx to about 1.4 MiB.
	r.Body = http.MaxBytesReader(w, r.Body, maxMessageBytes*2+4096)
	defer r.Body.Close()

	var input struct {
		Cipherx  string `json:"cipherx"`
		MaxViews *int   `json:"maxViews"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected JSON body with cipherx"})
		return
	}
	if input.Cipherx == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cipherx must not be empty"})
		return
	}
	cipherx, err := base64.RawURLEncoding.DecodeString(input.Cipherx)
	if err != nil || len(cipherx) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cipherx must be unpadded base64url"})
		return
	}
	if len(cipherx) > maxMessageBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "cipherx exceeds 1 MiB"})
		return
	}
	maxViews := 1
	if input.MaxViews != nil {
		maxViews = *input.MaxViews
	}
	if maxViews < 1 || maxViews > 1000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "maxViews must be between 1 and 1000"})
		return
	}
	id, err := randomID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "secure ID generation failed"})
		return
	}
	if !s.store.put(id, Message{
		Cipherx:   input.Cipherx,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(s.ttl).UTC(),
		MaxViews:  maxViews,
	}) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "message store is full; try again later"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":             id,
		"expiresIn":      s.ttl.String(),
		"maxViews":       maxViews,
		"viewsUsed":      0,
		"viewsRemaining": maxViews,
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid message ID"})
		return
	}
	msg, remaining, ok := s.store.view(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "message not found, expired, or its view limit has been reached"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cipherx":        msg.Cipherx,
		"createdAt":      msg.CreatedAt.Format(time.RFC3339),
		"expiresAt":      msg.ExpiresAt.Format(time.RFC3339),
		"maxViews":       msg.MaxViews,
		"viewsUsed":      msg.ViewsUsed,
		"viewsRemaining": remaining,
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	used, limit := s.store.stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"storeUsed":  used,
		"storeLimit": limit,
	})
}

func main() {
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	ttl := 24 * time.Hour
	if raw := os.Getenv("MESSAGE_TTL"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			log.Fatal("MESSAGE_TTL must be a positive Go duration, e.g. 24h")
		}
		ttl = parsed
	}
	storeLimit := 1000
	if raw := os.Getenv("STORE_LIMIT"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			log.Fatal("STORE_LIMIT must be a positive integer, e.g. 1000")
		}
		storeLimit = parsed
	}
	store := NewStore(storeLimit)
	go store.cleanupLoop()
	srv := &Server{store: store, ttl: ttl}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/messages", srv.create)
	mux.HandleFunc("/api/cipherxs", srv.createCipherx)
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
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("Vernam Share listening on %s (message TTL %s, store limit %d)", addr, ttl, storeLimit)
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
