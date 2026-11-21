package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// isolate points the config file at a temp path and clears the env that Resolve reads.
func isolate(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sub", "config.json")
	t.Setenv("WARPVAULT_CONFIG", path)
	t.Setenv("WARPVAULT_SERVER", "")
	t.Setenv("WARPVAULT_AUTH_TOKEN", "")
	return path
}

func TestResolvePrecedence(t *testing.T) {
	isolate(t)
	check := func(flag, want string, wantSrc Source) {
		t.Helper()
		got, src, err := Resolve(flag)
		if err != nil || got != want || src != wantSrc {
			t.Fatalf("Resolve(%q) = %q, %q, %v; want %q, %q", flag, got, src, err, want, wantSrc)
		}
	}
	check("", DefaultServer, FromDefault)

	if err := (File{Server: "files.example.com/"}).Save(); err != nil {
		t.Fatal(err)
	}
	check("", "https://files.example.com", FromFile)

	t.Setenv("WARPVAULT_SERVER", "http://localhost:8080")
	check("", "http://localhost:8080", FromEnv)
	check("flag.example.com", "https://flag.example.com", FromFlag)
}

func TestNormalizeServerRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "ftp://x.com", "http://", "https://a b.com"} {
		if got, err := NormalizeServer(bad); err == nil {
			t.Errorf("NormalizeServer(%q) = %q, want an error", bad, got)
		}
	}
}

func TestSaveLoadRoundTripAndPermissions(t *testing.T) {
	path := isolate(t)
	want := File{Server: "https://v.example.com", AuthToken: "tok"}
	if err := want.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil || got != want {
		t.Fatalf("Load() = %+v, %v; want %+v", got, err, want)
	}
	if runtime.GOOS != "windows" { // permission bits mean nothing on Windows
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("config file mode = %v, %v; want 0600", info.Mode().Perm(), err)
		}
	}
}

func TestLoadMissingAndMalformed(t *testing.T) {
	path := isolate(t)
	if f, err := Load(); err != nil || f != (File{}) {
		t.Fatalf("missing file: %+v, %v", f, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("malformed file must be an error, not silently ignored")
	}
	// ...but an explicit flag must still work with a broken file.
	if got, src, err := Resolve("x.example.com"); err != nil || got != "https://x.example.com" || src != FromFlag {
		t.Fatalf("flag with broken config: %q %q %v", got, src, err)
	}
}

// A saved token must never be sent to a server other than the one it was saved for.
func TestSavedTokenOnlyForItsServer(t *testing.T) {
	isolate(t)
	if err := (File{Server: "https://mine.example.com", AuthToken: "secret"}).Save(); err != nil {
		t.Fatal(err)
	}
	if tok, src := ResolveAuth("", "https://mine.example.com"); tok != "secret" || src != FromFile {
		t.Fatalf("own server: %q %q", tok, src)
	}
	if tok, _ := ResolveAuth("", "https://other.example.com"); tok != "" {
		t.Fatalf("token leaked to a different server: %q", tok)
	}
	if tok, _ := ResolveAuth("", DefaultServer); tok != "" {
		t.Fatalf("token leaked to the default server: %q", tok)
	}

	t.Setenv("WARPVAULT_AUTH_TOKEN", "env-tok")
	if tok, src := ResolveAuth("", "https://other.example.com"); tok != "env-tok" || src != FromEnv {
		t.Fatalf("env token is explicit and applies anywhere: %q %q", tok, src)
	}
	if tok, src := ResolveAuth("flag-tok", "https://other.example.com"); tok != "flag-tok" || src != FromFlag {
		t.Fatalf("flag token: %q %q", tok, src)
	}
}

func TestTokenWithoutSavedServerBelongsToDefault(t *testing.T) {
	isolate(t)
	if err := (File{AuthToken: "t"}).Save(); err != nil {
		t.Fatal(err)
	}
	if tok, _ := ResolveAuth("", DefaultServer); tok != "t" {
		t.Fatal("token saved without a server should apply to the default server")
	}
	if tok, _ := ResolveAuth("", "https://x.example.com"); tok != "" {
		t.Fatal("...and only to it")
	}
}
