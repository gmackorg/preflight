package main

import "testing"

// A source-binding field the runner cannot determine locally must not be read as
// a contradiction.
//
// Only app.json is parsed structurally. A dynamic app.config.js falls back to
// scraping the source for a quoted literal, so the idiomatic Expo pattern
// `bundleIdentifier: variant.iosBundleIdentifier` scrapes to "". Treating that
// as a mismatch made validation unsatisfiable for any variant-driven config: the
// runner claimed the development-lane device.discover job, rejected it with
// "iosBundleId expected com.gmacko.streamconductor.expo but local value was
// empty", and the workflow never got a device target.
func TestCompareSourceBindingValue(t *testing.T) {
	cases := []struct {
		name     string
		expected string
		actual   string
		wantErr  bool
	}{
		{"matching values pass", "com.gmacko.app", "com.gmacko.app", false},
		{"no expectation is not checked", "", "com.gmacko.app", false},
		{"an undeterminable local value is not a mismatch", "com.gmacko.app", "", false},
		{"whitespace-only local value is undeterminable too", "com.gmacko.app", "   ", false},
		{"a genuine disagreement still fails", "com.gmacko.app", "com.other.app", true},
		{"surrounding whitespace is ignored", " com.gmacko.app ", "com.gmacko.app", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := compareSourceBindingValue("iosBundleId", c.expected, c.actual)
			if c.wantErr && err == nil {
				t.Fatalf("expected a mismatch error for expected=%q actual=%q", c.expected, c.actual)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error for expected=%q actual=%q: %v", c.expected, c.actual, err)
			}
		})
	}
}
