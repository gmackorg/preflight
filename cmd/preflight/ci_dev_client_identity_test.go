package main

import "testing"

// A CI enqueue binds only the checkout (expoConfigDigest "sha256:ci-deferred"),
// so the app's scheme and bundle id are blank. Without them the dev-client
// deep link falls back to exp:// — Expo Go's scheme — which the installed dev
// build does not register, and `simctl openurl` fails with
// LSApplicationWorkspaceErrorDomain 115.
func TestHydrateBindingIdentityFillsBlankFieldsFromExpoConfig(t *testing.T) {
	binding := runnerJobSourceBinding{}
	hydrateBindingIdentity(&binding, expoAppIdentity{
		scheme:         "bob-dev",
		slug:           "bob",
		iosBundleID:    "com.gmacko.bob.dev",
		androidPackage: "com.gmacko.bob.dev",
	})
	if binding.AppScheme != "bob-dev" || binding.ExpoSlug != "bob" ||
		binding.IOSBundleID != "com.gmacko.bob.dev" || binding.AndroidPackage != "com.gmacko.bob.dev" {
		t.Fatalf("blank identity not hydrated: %+v", binding)
	}
	if got := appSchemeForDevelopmentClient(binding); got != "bob-dev" {
		t.Fatalf("dev-client scheme = %q, want bob-dev (not the exp fallback)", got)
	}
}

func TestHydrateBindingIdentityKeepsBoundValues(t *testing.T) {
	binding := runnerJobSourceBinding{AppScheme: "bound", IOSBundleID: "com.bound.app"}
	hydrateBindingIdentity(&binding, expoAppIdentity{scheme: "config", iosBundleID: "com.config.app", slug: "s"})
	if binding.AppScheme != "bound" || binding.IOSBundleID != "com.bound.app" {
		t.Fatalf("bound identity overwritten: %+v", binding)
	}
	if binding.ExpoSlug != "s" {
		t.Fatalf("blank slug not filled: %+v", binding)
	}
}
