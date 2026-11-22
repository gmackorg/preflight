package main

// Literal secret redaction (PREFLT-66).
//
// redactSetupTranscriptText recognises secrets by shape (KEY=value, bearer
// headers, JSON private_key fields). Store signing handles values that have no
// recognisable shape — keychain and keystore passwords, p12/keystore/p8 bytes,
// OAuth access tokens — so the job that reveals them registers the literal
// values here for as long as it holds them, and every command log line, job
// log chunk and failure message passes through redactRegisteredSecrets.

import (
	"sort"
	"strings"
	"sync"
)

// Shorter values would redact ordinary words in build logs.
const minRegisteredSecretLength = 6

var registeredSecrets = struct {
	mu     sync.RWMutex
	counts map[string]int
	sorted []string
}{counts: map[string]int{}}

// registerRedactedSecrets adds literal values to the redactor and returns a
// release func that removes them again. Multi-line values (PEM keys, JSON)
// also register each long line, because logs are redacted line by line.
func registerRedactedSecrets(values ...string) func() {
	expanded := []string{}
	for _, value := range values {
		expanded = append(expanded, redactionFragments(value)...)
	}
	registeredSecrets.mu.Lock()
	for _, value := range expanded {
		registeredSecrets.counts[value]++
	}
	rebuildRegisteredSecretsLocked()
	registeredSecrets.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			registeredSecrets.mu.Lock()
			for _, value := range expanded {
				registeredSecrets.counts[value]--
				if registeredSecrets.counts[value] <= 0 {
					delete(registeredSecrets.counts, value)
				}
			}
			rebuildRegisteredSecretsLocked()
			registeredSecrets.mu.Unlock()
		})
	}
}

func redactionFragments(value string) []string {
	fragments := []string{}
	trimmed := strings.TrimSpace(value)
	if len(trimmed) >= minRegisteredSecretLength {
		fragments = append(fragments, trimmed)
	}
	if strings.ContainsAny(trimmed, "\n") || strings.Contains(trimmed, `\n`) {
		normalized := strings.ReplaceAll(trimmed, `\n`, "\n")
		for _, line := range strings.Split(normalized, "\n") {
			line = strings.TrimSpace(line)
			// PEM armour lines are public and would hide useful context.
			if len(line) < 16 || strings.HasPrefix(line, "-----") {
				continue
			}
			fragments = append(fragments, line)
		}
	}
	return fragments
}

func rebuildRegisteredSecretsLocked() {
	sorted := make([]string, 0, len(registeredSecrets.counts))
	for value := range registeredSecrets.counts {
		sorted = append(sorted, value)
	}
	// Longest first so a value containing another is replaced whole.
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	registeredSecrets.sorted = sorted
}

func redactRegisteredSecrets(text string) string {
	registeredSecrets.mu.RLock()
	defer registeredSecrets.mu.RUnlock()
	for _, value := range registeredSecrets.sorted {
		if strings.Contains(text, value) {
			text = strings.ReplaceAll(text, value, "[REDACTED]")
		}
	}
	return text
}
