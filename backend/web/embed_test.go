package web

import (
	"io/fs"
	"testing"
)

func TestFS(t *testing.T) {
	if _, err := fs.Stat(FS(), ".gitkeep"); err != nil {
		if _, err2 := fs.Stat(FS(), "index.html"); err2 != nil {
			t.Fatalf("embedded dist has neither .gitkeep nor index.html: %v", err)
		}
	}
}
