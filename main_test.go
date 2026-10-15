package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCreateCipherxStoresCipherxWithoutReturningKey(t *testing.T) {
	store := NewStore()
	srv := &Server{store: store, ttl: 24 * time.Hour}
	cipherx := base64.RawURLEncoding.EncodeToString([]byte{0x10, 0x20, 0x30})
	body := []byte(`{"cipherx":"` + cipherx + `","maxViews":3}`)
	req := httptest.NewRequest(http.MethodPost, "/api/cipherxs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.createCipherx(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if _, ok := response["key"]; ok {
		t.Fatal("cipherx endpoint must not return a key")
	}
	if _, ok := response["message"]; ok {
		t.Fatal("cipherx endpoint must not return plaintext")
	}
	id, ok := response["id"].(string)
	if !ok || id == "" {
		t.Fatal("response missing message ID")
	}
	msg, remaining, ok := store.view(id)
	if !ok {
		t.Fatal("stored message could not be retrieved")
	}
	if msg.Cipherx != cipherx {
		t.Fatalf("stored cipherx = %q, want %q", msg.Cipherx, cipherx)
	}
	if msg.MaxViews != 3 || msg.ViewsUsed != 1 || remaining != 2 {
		t.Fatalf("unexpected view state: max=%d used=%d remaining=%d", msg.MaxViews, msg.ViewsUsed, remaining)
	}
}

func TestCreateCipherxRejectsPlaintextPayload(t *testing.T) {
	srv := &Server{store: NewStore(), ttl: time.Hour}
	req := httptest.NewRequest(http.MethodPost, "/api/cipherxs", strings.NewReader(`{"message":"plaintext","maxViews":3}`))
	rec := httptest.NewRecorder()
	srv.createCipherx(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestStoreLimitAndStats(t *testing.T) {
	store := NewStore(1)
	now := time.Now().UTC()
	msg := Message{
		Cipherx:   "Y2lwaGVy",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		MaxViews:  1,
	}
	if !store.put("first", msg) {
		t.Fatal("first message should fit in empty store")
	}
	if store.put("second", msg) {
		t.Fatal("store should reject messages above its configured limit")
	}
	used, limit := store.stats()
	if used != 1 || limit != 1 {
		t.Fatalf("stats = used:%d limit:%d, want used:1 limit:1", used, limit)
	}
}

func TestHealthReportsStoreUsageAndLimit(t *testing.T) {
	store := NewStore(7)
	now := time.Now().UTC()
	if !store.put("first", Message{
		Cipherx:   "Y2lwaGVy",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		MaxViews:  1,
	}) {
		t.Fatal("failed to seed store")
	}
	srv := &Server{store: store, ttl: time.Hour}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.health(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d, want %d", rec.Code, http.StatusOK)
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["status"] != "ok" {
		t.Fatalf("status = %v, want ok", response["status"])
	}
	if response["storeUsed"] != float64(1) || response["storeLimit"] != float64(7) {
		t.Fatalf("unexpected store stats: %#v", response)
	}
}

func TestCreateCipherxReturnsServiceUnavailableWhenStoreFull(t *testing.T) {
	store := NewStore(1)
	now := time.Now().UTC()
	if !store.put("existing", Message{
		Cipherx:   "Y2lwaGVy",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		MaxViews:  1,
	}) {
		t.Fatal("failed to seed full store")
	}
	srv := &Server{store: store, ttl: time.Hour}
	cipherx := base64.RawURLEncoding.EncodeToString([]byte{0x10, 0x20})
	req := httptest.NewRequest(http.MethodPost, "/api/cipherxs", strings.NewReader(`{"cipherx":"`+cipherx+`"}`))
	rec := httptest.NewRecorder()
	srv.createCipherx(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}
