package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Maestro grants iOS permissions through applesimutils: first a pinned copy
// in ~/.maestro/deps, then whatever `applesimutils` is on PATH. applesimutils
// only searches CoreSimulator's default device set, so it never finds a
// SimLock simulator ("No simulator found matching udid"), and launchApp fails
// with "Unable to set permissions". Maestro only logs the pinned copy's
// failure, so a SimLock lease puts this translator first on PATH: it carries
// out --setPermissions with `simctl privacy` inside the lease's device set.
const simlockAppleSimutilsCommand = "internal-simlock-applesimutils"

// applesimutils permission names that `simctl privacy` can set, mapped to its
// service names. Names absent here (camera, notifications, faceid, health,
// homekit, speech, userTracking, ...) have no simctl equivalent.
var appleSimutilsPrivacyServices = map[string]string{
	"calendar":     "calendar",
	"contacts":     "contacts",
	"location":     "location",
	"photos":       "photos",
	"medialibrary": "media-library",
	"microphone":   "microphone",
	"motion":       "motion",
	"reminders":    "reminders",
	"siri":         "siri",
}

type simctlPrivacyChange struct {
	action  string
	service string
}

// appleSimutilsPrivacyChanges turns one applesimutils permission (name=value)
// into simctl privacy changes. ok is false for a permission simctl cannot set.
func appleSimutilsPrivacyChanges(name, value string) (changes []simctlPrivacyChange, ok bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	value = strings.ToLower(strings.TrimSpace(value))
	service, known := appleSimutilsPrivacyServices[name]
	if !known {
		return nil, false
	}
	switch name {
	case "location":
		switch value {
		case "always":
			return []simctlPrivacyChange{{"grant", "location-always"}}, true
		case "inuse", "yes":
			return []simctlPrivacyChange{{"grant", "location"}}, true
		case "never", "no":
			return []simctlPrivacyChange{{"revoke", "location-always"}, {"revoke", "location"}}, true
		case "unset":
			return []simctlPrivacyChange{{"reset", "location-always"}, {"reset", "location"}}, true
		}
		return nil, false
	case "photos":
		if value == "limited" {
			return []simctlPrivacyChange{{"grant", "photos-add"}}, true
		}
	case "contacts":
		if value == "limited" {
			return []simctlPrivacyChange{{"grant", "contacts-limited"}}, true
		}
	}
	switch value {
	case "yes":
		return []simctlPrivacyChange{{"grant", service}}, true
	case "no":
		return []simctlPrivacyChange{{"revoke", service}}, true
	case "unset":
		return []simctlPrivacyChange{{"reset", service}}, true
	}
	return nil, false
}

// runSimlockAppleSimutils implements the applesimutils subset Maestro uses
// (--byId/--booted, --bundle, --setPermissions) against the leased simulator.
// Arguments: --lease <id> --device <udid> -- <applesimutils arguments>.
func runSimlockAppleSimutils(args []string, stdout io.Writer, stderr io.Writer) int {
	var leaseID, device string
	for len(args) > 0 && args[0] != "--" {
		if len(args) < 2 {
			fmt.Fprintln(stderr, "applesimutils (SimLock): missing value for", args[0])
			return 2
		}
		switch args[0] {
		case "--lease":
			leaseID = args[1]
		case "--device":
			device = args[1]
		default:
			fmt.Fprintln(stderr, "applesimutils (SimLock): unknown option", args[0])
			return 2
		}
		args = args[2:]
	}
	if len(args) > 0 {
		args = args[1:]
	}
	if leaseID == "" || device == "" {
		fmt.Fprintln(stderr, "applesimutils (SimLock): lease and device are required")
		return 2
	}
	var target, bundle, permissions string
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "--byId", "-id":
			target = next()
		case "--booted", "-bt":
			target = device
		case "--bundle", "-b":
			bundle = next()
		case "--setPermissions", "-sp":
			permissions = next()
		case "--byName", "-n", "--byOS", "-o", "--byType", "-t":
			next() // the leased device is the only one this lease may touch
		default:
			fmt.Fprintf(stderr, "applesimutils (SimLock): %s is not supported on a SimLock simulator; only --setPermissions is\n", args[i])
			return 1
		}
	}
	if target != "" && !strings.EqualFold(target, device) {
		fmt.Fprintf(stderr, "applesimutils (SimLock): simulator %s is not the leased device %s\n", target, device)
		return 1
	}
	if permissions == "" || bundle == "" {
		fmt.Fprintln(stderr, "applesimutils (SimLock): --setPermissions needs --bundle and a permission list")
		return 1
	}
	simlock, err := exec.LookPath("simlock")
	if err != nil {
		fmt.Fprintln(stderr, "applesimutils (SimLock): simlock CLI not found:", err)
		return 1
	}
	status := 0
	for _, entry := range strings.Split(permissions, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, value, found := strings.Cut(entry, "=")
		if !found {
			fmt.Fprintf(stderr, "applesimutils (SimLock): malformed permission %q\n", entry)
			status = 1
			continue
		}
		changes, ok := appleSimutilsPrivacyChanges(name, value)
		if !ok {
			// Leave it for the app's own prompt rather than fail the launch.
			fmt.Fprintf(stderr, "applesimutils (SimLock): skipped %s: simctl privacy cannot set it\n", entry)
			continue
		}
		for _, change := range changes {
			command := exec.Command(simlock, "--local", "simctl", "--lease", leaseID, "privacy", device, change.action, change.service, bundle)
			command.Env = os.Environ()
			command.Stdout = stdout
			command.Stderr = stderr
			if err := command.Run(); err != nil {
				fmt.Fprintf(stderr, "applesimutils (SimLock): simctl privacy %s %s: %v\n", change.action, change.service, err)
				status = 1
			}
		}
	}
	return status
}
