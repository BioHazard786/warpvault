package logger

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoggerInit(t *testing.T) {
	l := Init("debug", "text")
	if l == nil {
		t.Fatal("expected logger instance, got nil")
	}

	lj := Init("info", "json")
	if lj == nil {
		t.Fatal("expected json logger instance, got nil")
	}
}

func TestHTTPMiddleware(t *testing.T) {
	l := Init("info", "json")
	mw := HTTPMiddleware(l)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/api/info", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}
