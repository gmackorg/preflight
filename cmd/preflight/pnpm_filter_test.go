package main

import (
	"reflect"
	"testing"
)

func TestPnpmWorkspaceFilterBracesThePath(t *testing.T) {
	cases := map[string]string{
		"apps/mobile-bob":   "{./apps/mobile-bob}...",
		"./apps/mobile-bob": "{./apps/mobile-bob}...",
		"apps/mobile/":      "{./apps/mobile}...",
	}
	for in, want := range cases {
		got := pnpmWorkspaceFilter(in)
		if !reflect.DeepEqual(got, []string{"--filter", want}) {
			t.Errorf("pnpmWorkspaceFilter(%q) = %v, want [--filter %s]", in, got, want)
		}
	}
}
