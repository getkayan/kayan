package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspectLinks(t *testing.T) {
	dir := t.TempDir()
	guide := filepath.Join(dir, "guide.md")
	if err := os.WriteFile(guide, []byte("# Guide\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	document := filepath.Join(dir, "index.md")
	content := "[guide](./guide.md) [section](#local) [web](https://example.com)"
	if findings := inspectLinks(document, content); len(findings) != 0 {
		t.Fatalf("valid links reported as broken: %v", findings)
	}

	findings := inspectLinks(document, "[missing](./missing.md)")
	if len(findings) != 1 {
		t.Fatalf("inspectLinks() returned %d findings, want 1: %v", len(findings), findings)
	}
}
