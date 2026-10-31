package main

import (
	"reflect"
	"testing"
)

func TestStaleCIBuildProcessesRequiresCheckoutOwnership(t *testing.T) {
	const processes = `101 1 xcodebuild -workspace /build/.preflight-ci/foreign/apps/mobile/ios/Foreign.xcworkspace
202 1 xcodebuild -workspace /build/.preflight-ci/owned/apps/mobile/ios/Owned.xcworkspace
303 42 xcodebuild -workspace /build/.preflight-ci/owned/apps/mobile/ios/Owned.xcworkspace
404 1 expo run:ios --project /build/.preflight-ci/foreign/apps/mobile
505 1 xcodebuild -workspace /build/isolated/apps/mobile/ios/Local.xcworkspace
606 1 xcodebuild -workspace /build/.preflight-ci/owned-other/apps/mobile/ios/Other.xcworkspace
707 invalid xcodebuild -workspace /build/.preflight-ci/owned/apps/mobile/ios/Owned.xcworkspace
808 1 expo prebuild /build/.preflight-ci/owned/apps/mobile
`
	for _, tc := range []struct {
		name    string
		segment string
		want    []staleCIBuildProcess
	}{
		{name: "isolated checkout has no authority over CI builds"},
		{name: "whitespace is not ownership", segment: " "},
		{name: "foreign and live-parent builds survive", segment: "owned", want: []staleCIBuildProcess{{pid: 202, segment: "owned"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := staleCIBuildProcesses(processes, tc.segment); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("cleanup selected %v; want %v", got, tc.want)
			}
		})
	}
}
