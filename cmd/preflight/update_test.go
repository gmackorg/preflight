package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func TestParseChecksumsHandlesBothSha256sumFormats(t *testing.T) {
	// GNU sha256sum writes "*name" in binary mode; BSD/coreutils text mode
	// writes a bare name. A release built on either must verify.
	sums := parseChecksums(strings.Join([]string{
		"ABCD1234  preflight_darwin_arm64.tar.gz",
		"beef5678 *preflight_linux_amd64.tar.gz",
		"garbage-line-without-two-fields",
		"",
	}, "\n"))

	if got := sums["preflight_darwin_arm64.tar.gz"]; got != "abcd1234" {
		t.Fatalf("darwin checksum = %q, want lowercased abcd1234", got)
	}
	if got := sums["preflight_linux_amd64.tar.gz"]; got != "beef5678" {
		t.Fatalf("linux checksum = %q — the '*' binary-mode prefix must be stripped", got)
	}
	if len(sums) != 2 {
		t.Fatalf("parsed %d entries, want 2 (malformed lines ignored)", len(sums))
	}
}

func TestExtractBinaryFromTarGz(t *testing.T) {
	archive := tarGz(t, map[string]string{
		"README.md":   "not the binary",
		"./preflight": "BINARY-CONTENT",
	})
	got, err := extractBinaryFromTarGz(archive, "preflight")
	if err != nil {
		t.Fatal(err)
	}
	// Matched on base name so a "./" or directory prefix does not break it.
	if string(got) != "BINARY-CONTENT" {
		t.Fatalf("extracted %q, want BINARY-CONTENT", got)
	}
}

func TestExtractBinaryFromTarGzRejectsArchiveWithoutBinary(t *testing.T) {
	// Better to fail loudly than to install a README over the running binary.
	archive := tarGz(t, map[string]string{"README.md": "only docs"})
	if _, err := extractBinaryFromTarGz(archive, "preflight"); err == nil {
		t.Fatal("expected an error when the archive has no preflight binary")
	}
}

func TestAssetNameIsPlatformSpecific(t *testing.T) {
	name := assetName()
	if !strings.HasPrefix(name, "preflight_") || !strings.HasSuffix(name, ".tar.gz") {
		t.Fatalf("assetName() = %q, want preflight_<os>_<arch>.tar.gz", name)
	}
}

func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
