package main

// store.build for Android (PREFLT-66): expo prebuild, versionCode/versionName,
// gradle bundleRelease signed with the leased upload keystore through AGP's
// injected-signing properties, and a signature check of the output.

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// setAndroidVersion patches defaultConfig in android/app/build.gradle (Groovy,
// as Expo generates it) or build.gradle.kts.
func setAndroidVersion(appGradlePath string, versionName string, versionCode string) error {
	if _, err := strconv.ParseInt(versionCode, 10, 32); err != nil {
		return fmt.Errorf("buildNumber %q is not a valid Android versionCode", versionCode)
	}
	raw, err := os.ReadFile(appGradlePath)
	if err != nil {
		return err
	}
	content := string(raw)
	kotlin := strings.HasSuffix(appGradlePath, ".kts")
	quotedName := strconv.Quote(versionName)
	codeLine := "versionCode " + versionCode
	nameLine := "versionName " + quotedName
	codePattern := regexp.MustCompile(`(?m)^([ \t]*)versionCode[ \t]+[^\n]*$`)
	namePattern := regexp.MustCompile(`(?m)^([ \t]*)versionName[ \t]+[^\n]*$`)
	if kotlin {
		codeLine = "versionCode = " + versionCode
		nameLine = "versionName = " + quotedName
		codePattern = regexp.MustCompile(`(?m)^([ \t]*)versionCode[ \t]*=[^\n]*$`)
		namePattern = regexp.MustCompile(`(?m)^([ \t]*)versionName[ \t]*=[^\n]*$`)
	}
	defaultConfig := regexp.MustCompile(`(?m)^([ \t]*)defaultConfig[ \t]*\{[ \t]*\n`)
	location := defaultConfig.FindStringSubmatchIndex(content)
	if location == nil {
		return fmt.Errorf("%s has no defaultConfig block", appGradlePath)
	}
	open := location[1] - 2
	for open >= 0 && content[open] != '{' {
		open--
	}
	end := matchingBraceEnd(content, open)
	if end < 0 {
		return fmt.Errorf("%s defaultConfig block is unterminated", appGradlePath)
	}
	block := content[open:end]
	indent := content[location[2]:location[3]] + "    "
	for _, item := range []struct {
		pattern *regexp.Regexp
		line    string
	}{{codePattern, codeLine}, {namePattern, nameLine}} {
		if item.pattern.MatchString(block) {
			block = item.pattern.ReplaceAllString(block, "${1}"+strings.ReplaceAll(item.line, "$", "$$"))
			continue
		}
		block = "{\n" + indent + item.line + block[1:]
	}
	content = content[:open] + block + content[end:]
	return os.WriteFile(appGradlePath, []byte(content), 0o644)
}

func matchingBraceEnd(content string, open int) int {
	depth := 0
	for index := open; index < len(content); index++ {
		switch content[index] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return index + 1
			}
		}
	}
	return -1
}

var keytoolSHA1Pattern = regexp.MustCompile(`(?i)SHA-?1:\s*([0-9A-F:]{40,})`)
var apksignerSHA1Pattern = regexp.MustCompile(`(?i)certificate SHA-1 digest:\s*([0-9a-f]{40})`)

// androidSignatureSHA1 reads the signer fingerprint of an AAB (jar-signed, so
// keytool reads it) or an APK (apksigner when the SDK has it, since v2-only
// APKs have no JAR signature).
func androidSignatureSHA1(rt *storeJobRuntime, artifactPath string, kind string) (string, error) {
	if kind == "apk" {
		if apksigner := findAndroidBuildTool("apksigner"); apksigner != "" {
			output, err := rt.run.Run(storeCommand{Name: apksigner, Args: []string{"verify", "--print-certs", artifactPath}, Timeout: 5 * time.Minute})
			if err != nil {
				return "", fmt.Errorf("apksigner verify: %v: %s", err, strings.TrimSpace(string(output)))
			}
			if match := apksignerSHA1Pattern.FindStringSubmatch(string(output)); match != nil {
				return normalizeFingerprint(match[1]), nil
			}
			return "", fmt.Errorf("apksigner printed no SHA-1 digest")
		}
	}
	output, err := rt.run.Run(storeCommand{Name: "keytool", Args: []string{"-printcert", "-jarfile", artifactPath}, Timeout: 5 * time.Minute})
	if err != nil {
		return "", fmt.Errorf("keytool -printcert: %v: %s", err, strings.TrimSpace(string(output)))
	}
	match := keytoolSHA1Pattern.FindStringSubmatch(string(output))
	if match == nil {
		return "", fmt.Errorf("%s is not signed (keytool printed no SHA1)", filepath.Base(artifactPath))
	}
	return normalizeFingerprint(match[1]), nil
}

// findAndroidBuildTool returns the newest build-tools copy of a tool.
func findAndroidBuildTool(name string) string {
	for _, root := range androidSdkRoots() {
		matches, _ := filepath.Glob(filepath.Join(root, "build-tools", "*", name))
		if len(matches) > 0 {
			return matches[len(matches)-1]
		}
	}
	return ""
}

func androidGradleTask(plan storeBuildPlan) (string, string, string) {
	task := "bundleRelease"
	if plan.Android != nil && strings.TrimSpace(plan.Android.GradleTask) != "" {
		task = strings.TrimSpace(plan.Android.GradleTask)
	}
	if task == "assembleRelease" {
		return ":app:assembleRelease", "apk", filepath.Join("app", "build", "outputs", "apk", "release")
	}
	return ":app:bundleRelease", "aab", filepath.Join("app", "build", "outputs", "bundle", "release")
}

func runAndroidStoreBuild(rt *storeJobRuntime, plan storeBuildPlan, secretEnv map[string]string) (storeBuildOutcome, error) {
	revealed, err := revealStoreSecret(rt.reveal, rt.cleanup, plan.Android.KeystoreSecretReferenceID, "Android upload keystore")
	if err != nil {
		return storeBuildOutcome{}, err
	}
	var keystore androidUploadKeystorePayload
	if err := parseStoreSecretPayload("android_upload_keystore", revealed.Value, &keystore,
		"keystoreBase64", "keystorePassword", "keyAlias", "keyPassword", "sha1Fingerprint", "sha256Fingerprint"); err != nil {
		return storeBuildOutcome{}, err
	}
	registerPayloadSecrets(rt.cleanup, keystore.KeystorePassword, keystore.KeyPassword, keystore.KeystoreBase64)
	keystoreBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keystore.KeystoreBase64))
	if err != nil {
		return storeBuildOutcome{}, storeFailuref("signing_credential_invalid", "keystoreBase64 is not valid base64")
	}

	env, err := storeCommandEnv(plan.Environment, secretEnv)
	if err != nil {
		return storeBuildOutcome{}, err
	}
	if err := runExpoStorePrebuild(rt, "android", env); err != nil {
		return storeBuildOutcome{}, err
	}
	androidDir := filepath.Join(rt.appDir, "android")
	appGradle := filepath.Join(androidDir, "app", "build.gradle")
	if _, err := os.Stat(appGradle); err != nil {
		appGradle += ".kts"
	}
	if err := setAndroidVersion(appGradle, plan.Version, plan.BuildNumber); err != nil {
		return storeBuildOutcome{}, storeFailuref("android_project_patch_failed", "%v", err)
	}

	keystoreDir := filepath.Join(rt.workDir, "keystore")
	if err := os.MkdirAll(keystoreDir, 0o700); err != nil {
		return storeBuildOutcome{}, err
	}
	rt.cleanup.removeAll(keystoreDir)
	keystorePath := filepath.Join(keystoreDir, "upload.keystore")
	if err := os.WriteFile(keystorePath, keystoreBytes, 0o600); err != nil {
		return storeBuildOutcome{}, err
	}

	task, kind, outputDir := androidGradleTask(plan)
	_ = os.RemoveAll(filepath.Join(androidDir, outputDir))
	output, err := rt.run.Run(storeCommand{
		Name: "./gradlew",
		Args: []string{
			task,
			"--no-daemon",
			"-Pandroid.injected.signing.store.file=" + keystorePath,
			"-Pandroid.injected.signing.store.password=" + keystore.KeystorePassword,
			"-Pandroid.injected.signing.key.alias=" + keystore.KeyAlias,
			"-Pandroid.injected.signing.key.password=" + keystore.KeyPassword,
		},
		Dir:     androidDir,
		Env:     env,
		Timeout: storeCommandTimeout("PREFLIGHT_STORE_GRADLE_TIMEOUT", 60*time.Minute),
	})
	if err != nil {
		return storeBuildOutcome{}, wrapStoreCommandError(err, storeFailuref("gradle_build_failed", "gradle %s: %v%s", task, err, storeOutputTail(string(output))))
	}
	artifacts, _ := filepath.Glob(filepath.Join(androidDir, outputDir, "*."+kind))
	if len(artifacts) != 1 {
		return storeBuildOutcome{}, storeFailuref("gradle_build_failed", "gradle %s produced %d .%s files", task, len(artifacts), kind)
	}
	actual, err := androidSignatureSHA1(rt, artifacts[0], kind)
	if err != nil {
		return storeBuildOutcome{}, storeFailuref("signing_verification_failed", "%v", err)
	}
	if actual != normalizeFingerprint(keystore.SHA1Fingerprint) {
		return storeBuildOutcome{}, storeFailuref("signing_verification_failed", "%s is signed by %s, expected upload key %s", filepath.Base(artifacts[0]), actual, normalizeFingerprint(keystore.SHA1Fingerprint))
	}

	// Move the artifact into the job's output dir so store.upload on this
	// runner can reuse it by sha256.
	finalDir := filepath.Join(rt.workDir, "output")
	if err := os.MkdirAll(finalDir, 0o755); err != nil {
		return storeBuildOutcome{}, err
	}
	finalPath := filepath.Join(finalDir, filepath.Base(artifacts[0]))
	if err := os.Rename(artifacts[0], finalPath); err != nil {
		return storeBuildOutcome{}, err
	}
	return storeBuildOutcome{
		artifactPath: finalPath,
		kind:         kind,
		signing:      map[string]any{"keystoreSha1": normalizeFingerprintColons(keystore.SHA1Fingerprint)},
	}, nil
}

// normalizeFingerprintColons renders AA:BB:... as keytool prints it.
func normalizeFingerprintColons(value string) string {
	plain := normalizeFingerprint(value)
	pairs := []string{}
	for index := 0; index+2 <= len(plain); index += 2 {
		pairs = append(pairs, plain[index:index+2])
	}
	return strings.Join(pairs, ":")
}
