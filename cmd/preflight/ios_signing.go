package main

// Per-job iOS signing for store builds (PREFLT-66).
//
// The leased distribution certificate goes into a fresh keychain that exists
// only for this job; it joins the user keychain search list (Xcode's
// -exportArchive and codesign find identities there) and is removed from the
// list and deleted afterwards. Provisioning profiles are installed into both
// directories Xcode reads and removed again unless they were already there.
// Every step registers its undo on the job's storeCleanup before the next
// step runs, so a failure or cancellation part-way unwinds what was done.

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const storeSecurityTimeout = 2 * time.Minute

type iosSigningSession struct {
	keychainPath string
	password     string
}

// keychainSearchListMu serialises search-list edits inside this process; the
// flock in lockKeychainSearchList covers other runner agents on the host.
var keychainSearchListMu sync.Mutex

func lockKeychainSearchList() func() {
	keychainSearchListMu.Lock()
	lockPath := filepath.Join(os.TempDir(), "preflight-keychain-search-list.lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return keychainSearchListMu.Unlock
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
		keychainSearchListMu.Unlock()
	}
}

func parseKeychainList(output string) []string {
	list := []string{}
	for _, line := range strings.Split(output, "\n") {
		value := strings.Trim(strings.TrimSpace(line), `"`)
		if value = strings.TrimSpace(value); value != "" {
			list = append(list, value)
		}
	}
	return list
}

func randomKeychainPassword() (string, error) {
	buffer := make([]byte, 24)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func (rt *storeJobRuntime) security(args ...string) ([]byte, error) {
	return rt.run.Run(storeCommand{Name: "security", Args: args, Timeout: storeSecurityTimeout, Quiet: true})
}

// installIOSSigning creates the job keychain, imports the certificate (and
// the WWDR intermediate) and installs the profiles.
func installIOSSigning(rt *storeJobRuntime, jobID string, cert iosCertificatePayload, profiles []iosProvisioningProfilePayload) (*iosSigningSession, error) {
	password, err := randomKeychainPassword()
	if err != nil {
		return nil, err
	}
	registerPayloadSecrets(rt.cleanup, password)
	keychainDir := filepath.Join(rt.workDir, "keychain")
	if err := os.MkdirAll(keychainDir, 0o700); err != nil {
		return nil, err
	}
	rt.cleanup.removeAll(keychainDir)
	session := &iosSigningSession{
		keychainPath: filepath.Join(keychainDir, "preflight-store-"+sanitizeKeychainName(jobID)+".keychain-db"),
		password:     password,
	}

	if output, err := rt.security("create-keychain", "-p", password, session.keychainPath); err != nil {
		return nil, storeFailuref("signing_keychain_failed", "create keychain: %v: %s", err, strings.TrimSpace(string(output)))
	}
	rt.cleanup.add("delete job keychain", func() error {
		output, err := rt.security("delete-keychain", session.keychainPath)
		if err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(output)))
		}
		return nil
	})
	if output, err := rt.security("set-keychain-settings", "-lut", "21600", session.keychainPath); err != nil {
		return nil, storeFailuref("signing_keychain_failed", "set keychain settings: %v: %s", err, strings.TrimSpace(string(output)))
	}
	if output, err := rt.security("unlock-keychain", "-p", password, session.keychainPath); err != nil {
		return nil, storeFailuref("signing_keychain_failed", "unlock keychain: %v: %s", err, strings.TrimSpace(string(output)))
	}

	p12, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cert.P12Base64))
	if err != nil {
		return nil, storeFailuref("signing_credential_invalid", "certificate p12Base64 is not valid base64")
	}
	p12Path := filepath.Join(keychainDir, "certificate.p12")
	if err := os.WriteFile(p12Path, p12, 0o600); err != nil {
		return nil, err
	}
	rt.cleanup.removeFile(p12Path)
	output, err := rt.security("import", p12Path, "-k", session.keychainPath, "-f", "pkcs12", "-P", cert.P12Password,
		"-T", "/usr/bin/codesign", "-T", "/usr/bin/security")
	_ = os.Remove(p12Path)
	if err != nil {
		return nil, storeFailuref("signing_certificate_import_failed", "import distribution certificate: %v: %s", err, strings.TrimSpace(string(output)))
	}

	wwdrImported := false
	if pem := rt.wwdrPEM(); len(pem) > 0 {
		wwdrPath := filepath.Join(keychainDir, "wwdr.pem")
		if err := os.WriteFile(wwdrPath, pem, 0o600); err == nil {
			rt.cleanup.removeFile(wwdrPath)
			if output, err := rt.security("import", wwdrPath, "-k", session.keychainPath); err != nil && !strings.Contains(string(output), "already exists") {
				_, _ = fmt.Fprintf(rt.log, "warning: WWDR intermediate import failed: %s\n", strings.TrimSpace(string(output)))
			} else {
				wwdrImported = true
			}
		}
	}

	if output, err := rt.security("set-key-partition-list", "-S", "apple-tool:,apple:,codesign:", "-s", "-k", password, session.keychainPath); err != nil {
		return nil, storeFailuref("signing_keychain_failed", "set key partition list: %v: %s", err, strings.TrimSpace(string(output)))
	}

	if err := addKeychainToSearchList(rt, session.keychainPath); err != nil {
		return nil, err
	}

	identities, err := rt.security("find-identity", "-v", "-p", "codesigning", session.keychainPath)
	if err != nil || !strings.Contains(strings.ToUpper(string(identities)), normalizeFingerprint(cert.SHA1Fingerprint)) {
		hint := ""
		if !wwdrImported {
			hint = " (no Apple WWDR intermediate was available: set PREFLIGHT_SIGNING_WWDR_PEM or configure the fleet signing cert)"
		}
		return nil, storeFailuref("signing_identity_invalid", "certificate %s is not a valid codesigning identity in the job keychain%s", cert.SHA1Fingerprint, hint)
	}

	for _, profile := range profiles {
		if err := installProvisioningProfile(rt, jobID, profile); err != nil {
			return nil, err
		}
	}
	return session, nil
}

func sanitizeKeychainName(value string) string {
	cleaned := regexp.MustCompile(`[^A-Za-z0-9_-]`).ReplaceAllString(value, "_")
	if cleaned == "" {
		return "job"
	}
	return cleaned
}

// addKeychainToSearchList prepends the job keychain to the user search list
// and registers the removal. Removal takes the job keychain out of whatever
// the list is at that moment, which is the original list unless another job
// changed it in between — in which case that job's keychain is kept.
func addKeychainToSearchList(rt *storeJobRuntime, keychainPath string) error {
	unlock := lockKeychainSearchList()
	defer unlock()
	output, err := rt.security("list-keychains", "-d", "user")
	if err != nil {
		return storeFailuref("signing_keychain_failed", "read keychain search list: %v", err)
	}
	original := parseKeychainList(string(output))
	_, _ = fmt.Fprintf(rt.log, "keychain search list before store signing: %s\n", strings.Join(original, ", "))
	updated := append([]string{keychainPath}, removeString(original, keychainPath)...)
	if output, err := rt.security(append([]string{"list-keychains", "-d", "user", "-s"}, updated...)...); err != nil {
		return storeFailuref("signing_keychain_failed", "update keychain search list: %v: %s", err, strings.TrimSpace(string(output)))
	}
	rt.cleanup.add("restore keychain search list", func() error {
		unlock := lockKeychainSearchList()
		defer unlock()
		output, err := rt.security("list-keychains", "-d", "user")
		if err != nil {
			return err
		}
		current := parseKeychainList(string(output))
		restored := removeString(current, keychainPath)
		if len(restored) == 0 {
			restored = original
		}
		if output, err := rt.security(append([]string{"list-keychains", "-d", "user", "-s"}, restored...)...); err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(output)))
		}
		return nil
	})
	return nil
}

func removeString(values []string, unwanted string) []string {
	kept := []string{}
	for _, value := range values {
		if value != unwanted {
			kept = append(kept, value)
		}
	}
	return kept
}

func normalizeFingerprint(value string) string {
	return strings.ToUpper(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(value)))
}

// iosProvisioningProfileDirs are the two places Xcode reads profiles from;
// Xcode 16+ only reads the UserData one.
func iosProvisioningProfileDirs(home string) []string {
	return []string{
		filepath.Join(home, "Library", "MobileDevice", "Provisioning Profiles"),
		filepath.Join(home, "Library", "Developer", "Xcode", "UserData", "Provisioning Profiles"),
	}
}

func profileLeaseDir(home string, uuid string) string {
	return filepath.Join(home, "Library", "Caches", "preflight", "profile-leases", uuid)
}

// installProvisioningProfile installs a profile for the duration of the job.
// Several runner agents share a Mac and may build the same app at once, so a
// lease file per job marks the profile in use; the last job out removes it.
// A profile that was already installed by someone else is never removed.
func installProvisioningProfile(rt *storeJobRuntime, jobID string, profile iosProvisioningProfilePayload) error {
	uuid := strings.TrimSpace(profile.UUID)
	if !regexp.MustCompile(`^[A-Za-z0-9-]+$`).MatchString(uuid) {
		return storeFailuref("signing_credential_invalid", "provisioning profile for %s has an invalid uuid", profile.BundleID)
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(profile.ProfileBase64))
	if err != nil {
		return storeFailuref("signing_credential_invalid", "provisioning profile for %s is not valid base64", profile.BundleID)
	}
	leaseDir := profileLeaseDir(rt.homeDir, uuid)
	if err := os.MkdirAll(leaseDir, 0o700); err != nil {
		return err
	}
	otherLeases, _ := os.ReadDir(leaseDir)
	leasePath := filepath.Join(leaseDir, sanitizeKeychainName(jobID))
	if err := os.WriteFile(leasePath, []byte(time.Now().UTC().Format(time.RFC3339)), 0o600); err != nil {
		return err
	}
	installed := []string{}
	for _, dir := range iosProvisioningProfileDirs(rt.homeDir) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		path := filepath.Join(dir, uuid+".mobileprovision")
		if existing, err := os.ReadFile(path); err == nil {
			if len(otherLeases) == 0 {
				// Installed outside Preflight: the same uuid is the same
				// profile, so use it and leave it exactly as found.
				continue
			}
			// Installed by another Preflight job still holding a lease: share
			// it; whichever job finishes last removes it.
			installed = append(installed, path)
			if string(existing) == string(data) {
				continue
			}
		} else {
			installed = append(installed, path)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(rt.log, "installed provisioning profile %s (%s) at %s\n", profile.Name, uuid, path)
	}
	rt.cleanup.add("remove provisioning profile "+uuid, func() error {
		_ = os.Remove(leasePath)
		remaining, _ := os.ReadDir(leaseDir)
		if len(remaining) > 0 {
			return nil
		}
		_ = os.Remove(leaseDir)
		for _, path := range installed {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		return nil
	})
	return nil
}

// wwdrPEM returns the Apple WWDR intermediate: PREFLIGHT_SIGNING_WWDR_PEM
// (PEM text or base64 of it), else the fleet signing-cert endpoint's
// wwdrPemBase64 — the same source installFleetSigningIdentity uses.
func (rt *storeJobRuntime) wwdrPEM() []byte {
	if pem := decodeWWDR(os.Getenv("PREFLIGHT_SIGNING_WWDR_PEM")); len(pem) > 0 {
		return pem
	}
	if rt.fetchWWDR != nil {
		return rt.fetchWWDR()
	}
	return nil
}

func decodeWWDR(value string) []byte {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if strings.Contains(value, "-----BEGIN") {
		return []byte(value + "\n")
	}
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded
	}
	return nil
}

func fetchWWDRIntermediate(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData) []byte {
	data, err := getPreflightJSON(client, runnerEndpoint(options.apiURL, fmt.Sprintf("/api/preflight/v1/runners/%s/signing-cert", registration.Runner.ID)), registration.Token)
	if err != nil {
		return nil
	}
	var cert fleetSigningCert
	if err := json.Unmarshal(data, &cert); err != nil {
		return nil
	}
	return decodeWWDR(cert.WWDRPemBase64)
}

// verifyIOSArchiveSignature unpacks the IPA and checks the app's signature
// is valid and was made by the leased certificate and team.
func verifyIOSArchiveSignature(rt *storeJobRuntime, ipaPath string, expectedSHA1 string, teamID string) error {
	verifyDir := filepath.Join(rt.workDir, "verify")
	_ = os.RemoveAll(verifyDir)
	if err := os.MkdirAll(verifyDir, 0o755); err != nil {
		return err
	}
	rt.cleanup.removeAll(verifyDir)
	if output, err := rt.run.Run(storeCommand{Name: "ditto", Args: []string{"-x", "-k", ipaPath, verifyDir}, Timeout: 10 * time.Minute}); err != nil {
		return storeFailuref("signing_verification_failed", "unpack IPA: %v: %s", err, strings.TrimSpace(string(output)))
	}
	apps, _ := filepath.Glob(filepath.Join(verifyDir, "Payload", "*.app"))
	if len(apps) != 1 {
		return storeFailuref("signing_verification_failed", "IPA has %d apps in Payload/", len(apps))
	}
	app := apps[0]
	if output, err := rt.run.Run(storeCommand{Name: "codesign", Args: []string{"--verify", "--deep", "--strict", "--verbose=2", app}, Timeout: 10 * time.Minute}); err != nil {
		return storeFailuref("signing_verification_failed", "codesign --verify: %v: %s", err, strings.TrimSpace(string(output)))
	}
	details, err := rt.run.Run(storeCommand{Name: "codesign", Args: []string{"-dv", "--verbose=4", app}, Timeout: 2 * time.Minute})
	if err != nil {
		return storeFailuref("signing_verification_failed", "codesign -dv: %v", err)
	}
	if match := regexp.MustCompile(`TeamIdentifier=(\S+)`).FindStringSubmatch(string(details)); match == nil || match[1] != teamID {
		found := ""
		if match != nil {
			found = match[1]
		}
		return storeFailuref("signing_verification_failed", "app is signed for team %q, expected %q", found, teamID)
	}
	certPrefix := filepath.Join(verifyDir, "signing-cert")
	if output, err := rt.run.Run(storeCommand{Name: "codesign", Args: []string{"-d", "--extract-certificates=" + certPrefix, app}, Timeout: 2 * time.Minute}); err != nil {
		return storeFailuref("signing_verification_failed", "extract signing certificate: %v: %s", err, strings.TrimSpace(string(output)))
	}
	leaf, err := os.ReadFile(certPrefix + "0")
	if err != nil {
		return storeFailuref("signing_verification_failed", "read extracted signing certificate: %v", err)
	}
	sum := sha1.Sum(leaf)
	if actual := strings.ToUpper(hex.EncodeToString(sum[:])); actual != normalizeFingerprint(expectedSHA1) {
		return storeFailuref("signing_verification_failed", "app is signed by certificate %s, expected %s", actual, normalizeFingerprint(expectedSHA1))
	}
	return nil
}
