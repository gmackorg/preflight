package main

// `preflight update` — pull the latest released binary from GitHub.
//
// The fleet had no runner-update path at all, which is how gmacko-mini ended up
// running an Aug-12 build with none of the disk-sweep fixes while labtop ran a
// current one. A version-skewed fleet silently loses fixes: the host that most
// needs a guard is the one least likely to have it.
//
// This binary runs builds with credentials on developer machines, so the
// download is verified against the checksums published with the release and
// installed atomically. A mismatch aborts without touching the existing binary.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Overridable so a fork or a mirror can point elsewhere without a rebuild.
func updateRepoSlug() string {
	if slug := strings.TrimSpace(os.Getenv("PREFLIGHT_UPDATE_REPO")); slug != "" {
		return slug
	}
	return "gmackorg/preflight"
}

type githubAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
	Size        int64  `json:"size"`
}

type githubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	Draft       bool          `json:"draft"`
	Prerelease  bool          `json:"prerelease"`
	PublishedAt string        `json:"published_at"`
	Assets      []githubAsset `json:"assets"`
}

// assetName is the per-platform archive published by the release workflow.
func assetName() string {
	return fmt.Sprintf("preflight_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
}

func runUpdate(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	checkOnly := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--help", "-h":
			fmt.Fprintln(stdout, "Usage: preflight update [--check]")
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "Install the latest released preflight binary from GitHub.")
			fmt.Fprintln(stdout, "  --check  report what is available without installing")
			fmt.Fprintln(stdout)
			fmt.Fprintf(stdout, "Source: https://github.com/%s/releases (override with PREFLIGHT_UPDATE_REPO)\n", updateRepoSlug())
			fmt.Fprintln(stdout, "The download is verified against the release checksums and installed")
			fmt.Fprintln(stdout, "atomically; a mismatch aborts without replacing the current binary.")
			return 0
		case "--check":
			checkOnly = true
		}
	}

	release, err := fetchLatestRelease(client)
	if err != nil {
		fmt.Fprintf(stderr, "check for updates failed: %v\n", err)
		return 1
	}
	latest := strings.TrimPrefix(release.TagName, "v")
	current := strings.TrimPrefix(preflightCLIVersion, "v")

	fmt.Fprintf(stdout, "current: %s\nlatest:  %s", current, latest)
	if release.PublishedAt != "" {
		fmt.Fprintf(stdout, "  (published %s)", release.PublishedAt)
	}
	fmt.Fprintln(stdout)

	if latest == current {
		fmt.Fprintln(stdout, "Already up to date.")
		return 0
	}
	if checkOnly {
		fmt.Fprintf(stdout, "Run `preflight update` to install %s.\n", latest)
		return 0
	}

	target, err := installPath()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}

	want := assetName()
	var asset *githubAsset
	for i := range release.Assets {
		if release.Assets[i].Name == want {
			asset = &release.Assets[i]
			break
		}
	}
	if asset == nil {
		// Naming the platform matters: "asset not found" alone sends people
		// looking at the network rather than at an unpublished architecture.
		fmt.Fprintf(stderr, "release %s has no asset for %s/%s (expected %s)\n",
			release.TagName, runtime.GOOS, runtime.GOARCH, want)
		return 1
	}

	sums, err := fetchChecksums(client, release)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	expected, ok := sums[asset.Name]
	if !ok {
		fmt.Fprintf(stderr, "release %s publishes no checksum for %s — refusing to install\n",
			release.TagName, asset.Name)
		return 1
	}

	fmt.Fprintf(stdout, "downloading %s (%.1f MB)...\n", asset.Name, float64(asset.Size)/(1024*1024))
	blob, err := download(client, asset.DownloadURL)
	if err != nil {
		fmt.Fprintf(stderr, "download failed: %v\n", err)
		return 1
	}
	got := sha256.Sum256(blob)
	if hex.EncodeToString(got[:]) != expected {
		fmt.Fprintf(stderr, "checksum mismatch for %s\n  expected %s\n  got      %s\nrefusing to install; the existing binary is untouched\n",
			asset.Name, expected, hex.EncodeToString(got[:]))
		return 1
	}
	fmt.Fprintln(stdout, "checksum ok")

	binary, err := extractBinaryFromTarGz(blob, "preflight")
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	if err := installAtomically(target, binary); err != nil {
		fmt.Fprintf(stderr, "install failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "installed %s to %s\n", latest, target)
	// A runner keeps its old code until the process restarts, which is exactly
	// the skew this command exists to remove — so say so rather than implying
	// the fleet is updated.
	fmt.Fprintln(stdout, "Running runners keep the old binary until restarted:")
	fmt.Fprintln(stdout, "  launchctl kickstart -k gui/$(id -u)/com.forgegraph.preflight-runner.<name>")
	return 0
}

func fetchLatestRelease(client *http.Client) (*githubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", updateRepoSlug())
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "preflight-cli")
	// A token is optional (public repo) but avoids the 60/hr anonymous limit.
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no published release found for %s", updateRepoSlug())
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("GitHub returned HTTP %d", response.StatusCode)
	}
	var release githubRelease
	if err := json.NewDecoder(response.Body).Decode(&release); err != nil {
		return nil, err
	}
	return &release, nil
}

// fetchChecksums parses the release's checksums.txt ("<sha256>  <filename>").
func fetchChecksums(client *http.Client, release *githubRelease) (map[string]string, error) {
	var url string
	for _, asset := range release.Assets {
		if asset.Name == "checksums.txt" {
			url = asset.DownloadURL
			break
		}
	}
	if url == "" {
		return nil, fmt.Errorf("release %s publishes no checksums.txt — refusing to install unverified", release.TagName)
	}
	blob, err := download(client, url)
	if err != nil {
		return nil, fmt.Errorf("fetch checksums: %w", err)
	}
	return parseChecksums(string(blob)), nil
}

func parseChecksums(body string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 {
			continue
		}
		// sha256sum writes "*name" for binary mode.
		out[strings.TrimPrefix(fields[1], "*")] = strings.ToLower(fields[0])
	}
	return out
}

func download(client *http.Client, url string) ([]byte, error) {
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "preflight-cli")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d fetching %s", response.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(response.Body, 128<<20))
}

// installPath resolves the binary to replace, refusing early when it is not
// writable — better than failing after a download.
func installPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate current binary: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	probe := filepath.Join(dir, ".preflight-update-probe")
	file, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("%s is not writable — reinstall with elevated permissions or move the binary somewhere you own", dir)
	}
	file.Close()
	os.Remove(probe)
	return exe, nil
}

// installAtomically writes beside the target then renames over it, so an
// interrupted update can never leave a half-written binary in place.
func installAtomically(target string, payload []byte) error {
	dir := filepath.Dir(target)
	temp, err := os.CreateTemp(dir, ".preflight-update-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)

	if _, err := temp.Write(payload); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tempName, 0o755); err != nil {
		return err
	}
	// Keep a copy of the outgoing binary: if the new one is broken, the
	// operator needs a way back that does not require network access.
	backup := target + ".previous"
	if existing, err := os.ReadFile(target); err == nil {
		_ = os.WriteFile(backup, existing, 0o755)
	}
	if err := os.Rename(tempName, target); err != nil {
		return fmt.Errorf("%w (previous binary preserved at %s)", err, backup)
	}
	_ = os.Chtimes(target, time.Now(), time.Now())
	return nil
}

// extractBinaryFromTarGz pulls a single named file out of the release archive.
// Entries are matched on base name so a leading "./" or directory prefix in the
// tarball does not break the update.
func extractBinaryFromTarGz(blob []byte, want string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return nil, fmt.Errorf("open release archive: %w", err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read release archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg || filepath.Base(header.Name) != want {
			continue
		}
		payload, err := io.ReadAll(io.LimitReader(reader, 256<<20))
		if err != nil {
			return nil, err
		}
		if len(payload) == 0 {
			return nil, fmt.Errorf("release archive contains an empty %s", want)
		}
		return payload, nil
	}
	return nil, fmt.Errorf("release archive does not contain %s", want)
}
