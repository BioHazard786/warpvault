package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseLink(t *testing.T) {
	srv, id, key, err := ParseLink("https://vault.example.com/v/a8X2mP9z#abc_DEF-123")
	if err != nil || srv != "https://vault.example.com" || id != "a8X2mP9z" || key != "abc_DEF-123" {
		t.Fatalf("got %q %q %q %v", srv, id, key, err)
	}
	for _, bad := range []string{"", "a8X2mP9z", "https://host/", "https://host/x/a8X2mP9z", "https://host/v/a/b"} {
		if _, _, _, err := ParseLink(bad); !errors.Is(err, ErrBadLink) {
			t.Errorf("ParseLink(%q): expected ErrBadLink, got %v", bad, err)
		}
	}
}

func TestCreateAndOpen(t *testing.T) {
	var gotAuth, gotQuery string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/vault", func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotQuery = r.Header.Get("X-Auth-Token"), r.URL.RawQuery
		body, _ := io.ReadAll(r.Body)
		if string(body) != "blob" {
			t.Errorf("body = %q", body)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"abc","url":"http://x/v/abc","delete_url":"http://x/d/t","delete_token":"t","burn":true}`))
	})
	mux.HandleFunc("POST /api/vault/abc/open", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("blob")) })
	mux.HandleFunc("POST /api/vault/gone/open", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusGone) })
	mux.HandleFunc("POST /api/vault/none/open", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := New(ts.URL, "tok")
	res, err := c.Create(context.Background(), []byte("blob"), "burn")
	if err != nil || res.ID != "abc" || !res.Burn || gotAuth != "tok" || gotQuery != "expiry=burn" {
		t.Fatalf("Create: %+v %v auth=%q query=%q", res, err, gotAuth, gotQuery)
	}
	if b, err := c.Open(context.Background(), "abc"); err != nil || string(b) != "blob" {
		t.Fatalf("Open: %q %v", b, err)
	}
	if _, err := c.Open(context.Background(), "gone"); !errors.Is(err, ErrBurned) {
		t.Errorf("410: got %v", err)
	}
	if _, err := c.Open(context.Background(), "none"); !errors.Is(err, ErrNotFound) {
		t.Errorf("404: got %v", err)
	}
}
