package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Expo can skip CocoaPods when package.json was changed before prebuild. The
// runner must refresh pods even when prebuild itself reports no changes.
func TestExpoPrebuildRefreshesExistingPods(t *testing.T) {
	app := t.TempDir()
	ios := filepath.Join(app, "ios")
	if err := os.MkdirAll(ios, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ios, "Podfile"), []byte("native graph"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ios, "Podfile.lock"), []byte("old graph"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "npx"), []byte("#!/bin/sh\nprintf 'Finished prebuild; unchanged package.json\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	pod := "#!/bin/sh\n[ \"$*\" = 'install' ] || exit 40\nprintf 'ExpoLocalAuthentication\\n' > Podfile.lock\n"
	if err := os.WriteFile(filepath.Join(bin, "pod"), []byte(pod), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	log, err := os.Create(filepath.Join(app, "build.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	if err := runExpoPrebuild(log, app, "ios", apiRunnerJob{}, nil); err != nil {
		t.Fatal(err)
	}
	lock, err := os.ReadFile(filepath.Join(ios, "Podfile.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lock), "ExpoLocalAuthentication") {
		t.Fatalf("prebuild left stale native module graph: %s", lock)
	}
	if err := os.WriteFile(filepath.Join(bin, "pod"), []byte("#!/bin/sh\nprintf 'pods failed\\n' >&2\nexit 42\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runExpoPrebuild(log, app, "ios", apiRunnerJob{}, nil); err == nil || !strings.Contains(err.Error(), "CocoaPods") {
		t.Fatalf("pod sync failure did not stop native build: %v", err)
	}
}
