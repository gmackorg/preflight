package main

// Xcode project patching for store builds (PREFLT-66): manual signing per
// target, version/build numbers, and the ExportOptions.plist for
// -exportArchive. The .pbxproj is an old-style (OpenStep) plist; Expo
// generates it, so a targeted text patch keeps every other line untouched.

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type pbxNativeTarget struct {
	ID          string
	Name        string
	ProductType string
	// Build configuration ids by configuration name.
	Configurations map[string]string
	// The configuration list's defaultConfigurationName.
	DefaultConfiguration string
	// Values of the archived configuration (see configurationID).
	BundleID  string
	InfoPlist string
}

// configurationID returns the id of the build configuration Xcode uses for
// this target when the archive builds the named configuration: the target's
// own configuration with that name, or else its defaultConfigurationName.
func (target pbxNativeTarget) configurationID(name string) string {
	if id := target.Configurations[name]; id != "" {
		return id
	}
	return target.Configurations[target.DefaultConfiguration]
}

// signableProductType: applications and app extensions each need their own
// distribution profile; frameworks and resource bundles do not.
func signableProductType(productType string) bool {
	switch productType {
	case "com.apple.product-type.application",
		"com.apple.product-type.application.messages",
		"com.apple.product-type.application.watchapp2",
		"com.apple.product-type.app-extension",
		"com.apple.product-type.app-extension.messages",
		"com.apple.product-type.app-extension.messages-sticker-pack",
		"com.apple.product-type.extensionkit-extension",
		"com.apple.product-type.watchkit2-extension":
		return true
	}
	return false
}

// pbxObjectRange returns [open, end) of the object `id = { ... };` where open
// is the index of '{' and end is one past the matching '}'.
func pbxObjectRange(content string, id string) (int, int, bool) {
	pattern := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(id) + `(?:[ \t]*/\*[^*]*\*/)?[ \t]*=[ \t]*\{`)
	location := pattern.FindStringIndex(content)
	if location == nil {
		return 0, 0, false
	}
	open := location[1] - 1
	end := pbxBlockEnd(content, open)
	if end < 0 {
		return 0, 0, false
	}
	return open, end, true
}

// pbxBlockEnd returns one past the brace matching content[open], skipping
// quoted strings and comments.
func pbxBlockEnd(content string, open int) int {
	depth := 0
	for index := open; index < len(content); index++ {
		switch content[index] {
		case '"':
			for index++; index < len(content) && content[index] != '"'; index++ {
				if content[index] == '\\' {
					index++
				}
			}
		case '/':
			if index+1 < len(content) && content[index+1] == '*' {
				closing := strings.Index(content[index+2:], "*/")
				if closing < 0 {
					return -1
				}
				index += closing + 3
			}
		case '{', '(':
			depth++
		case '}', ')':
			depth--
			if depth == 0 {
				return index + 1
			}
		}
	}
	return -1
}

// pbxTopLevelValue reads `key = value;` at depth 1 of the block body.
func pbxTopLevelValue(body string, key string) string {
	flattened := pbxStripNested(body)
	pattern := regexp.MustCompile(`(?m)^[ \t]*"?` + regexp.QuoteMeta(key) + `"?[ \t]*=[ \t]*("(?:[^"\\]|\\.)*"|[^;\n]*);`)
	match := pattern.FindStringSubmatch(flattened)
	if match == nil {
		return ""
	}
	return pbxUnquote(strings.TrimSpace(match[1]))
}

// pbxStripNested removes nested {...} and (...) values from a block body
// (the outer braces excluded) so top-level lookups cannot match inside them.
func pbxStripNested(body string) string {
	var out strings.Builder
	for index := 0; index < len(body); index++ {
		if body[index] == '"' {
			start := index
			for index++; index < len(body) && body[index] != '"'; index++ {
				if body[index] == '\\' {
					index++
				}
			}
			if index >= len(body) {
				out.WriteString(body[start:])
				break
			}
			out.WriteString(body[start : index+1])
			continue
		}
		if body[index] == '{' || body[index] == '(' {
			end := pbxBlockEnd(body, index)
			if end < 0 {
				break
			}
			out.WriteString("<nested>")
			index = end - 1
			continue
		}
		out.WriteByte(body[index])
	}
	return out.String()
}

func pbxUnquote(value string) string {
	if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		inner := value[1 : len(value)-1]
		inner = strings.ReplaceAll(inner, `\"`, `"`)
		inner = strings.ReplaceAll(inner, `\\`, `\`)
		return inner
	}
	return value
}

var pbxBareValue = regexp.MustCompile(`^[A-Za-z0-9_./]+$`)

func pbxQuote(value string) string {
	if pbxBareValue.MatchString(value) {
		return value
	}
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

// parsePBXNativeTargets lists the project's native targets with their
// configuration ids and the bundle id / Info.plist of the configuration the
// archive builds (Release unless the build profile names another one).
func parsePBXNativeTargets(content string, configuration string) ([]pbxNativeTarget, error) {
	isa := regexp.MustCompile(`(?m)^[ \t]*([0-9A-Fa-f]{24})(?:[ \t]*/\*[^*]*\*/)?[ \t]*=[ \t]*\{[ \t]*\n?[ \t]*isa = PBXNativeTarget;`)
	targets := []pbxNativeTarget{}
	for _, match := range isa.FindAllStringSubmatch(content, -1) {
		id := match[1]
		open, end, ok := pbxObjectRange(content, id)
		if !ok {
			continue
		}
		body := content[open+1 : end-1]
		target := pbxNativeTarget{
			ID:             id,
			Name:           pbxTopLevelValue(body, "name"),
			ProductType:    pbxTopLevelValue(body, "productType"),
			Configurations: map[string]string{},
		}
		listID := strings.Fields(pbxTopLevelValue(body, "buildConfigurationList"))
		if len(listID) > 0 {
			if listOpen, listEnd, ok := pbxObjectRange(content, listID[0]); ok {
				listBody := content[listOpen+1 : listEnd-1]
				target.DefaultConfiguration = pbxTopLevelValue(listBody, "defaultConfigurationName")
				configs := regexp.MustCompile(`buildConfigurations = \(([^)]*)\)`).FindStringSubmatch(listBody)
				if configs != nil {
					for _, configID := range regexp.MustCompile(`([0-9A-Fa-f]{24})`).FindAllString(configs[1], -1) {
						if configOpen, configEnd, ok := pbxObjectRange(content, configID); ok {
							name := pbxTopLevelValue(content[configOpen+1:configEnd-1], "name")
							target.Configurations[name] = configID
						}
					}
				}
			}
		}
		if configID := target.configurationID(configuration); configID != "" {
			target.BundleID = pbxBuildSetting(content, configID, "PRODUCT_BUNDLE_IDENTIFIER")
			target.InfoPlist = pbxBuildSetting(content, configID, "INFOPLIST_FILE")
		}
		targets = append(targets, target)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no native targets found in project")
	}
	return targets, nil
}

// pbxBuildSettingsRange returns [open, end) of a configuration's
// buildSettings block.
func pbxBuildSettingsRange(content string, configID string) (int, int, bool) {
	open, end, ok := pbxObjectRange(content, configID)
	if !ok {
		return 0, 0, false
	}
	location := regexp.MustCompile(`buildSettings = \{`).FindStringIndex(content[open:end])
	if location == nil {
		return 0, 0, false
	}
	settingsOpen := open + location[1] - 1
	settingsEnd := pbxBlockEnd(content, settingsOpen)
	if settingsEnd < 0 {
		return 0, 0, false
	}
	return settingsOpen, settingsEnd, true
}

func pbxBuildSetting(content string, configID string, key string) string {
	open, end, ok := pbxBuildSettingsRange(content, configID)
	if !ok {
		return ""
	}
	return pbxTopLevelValue(content[open+1:end-1], key)
}

// pbxSetInBlock sets (or, with remove, deletes) top-level scalar keys inside
// the block whose '{' is at open. Returns the new content.
func pbxSetInBlock(content string, open int, settings map[string]string, remove []string) (string, error) {
	end := pbxBlockEnd(content, open)
	if end < 0 {
		return content, fmt.Errorf("unterminated block")
	}
	body := content[open+1 : end-1]
	indent := "\t\t\t\t"
	if match := regexp.MustCompile(`\n([ \t]+)\S`).FindStringSubmatch(body); match != nil {
		indent = match[1]
	}
	keyPattern := func(key string) *regexp.Regexp {
		return regexp.MustCompile(`(?m)^[ \t]*(?:"` + regexp.QuoteMeta(key) + `"|` + regexp.QuoteMeta(key) + `)[ \t]*=[ \t]*(?:"(?:[^"\\]|\\.)*"|[^;\n(]*);[ \t]*\n`)
	}
	for _, key := range remove {
		body = keyPattern(key).ReplaceAllString(body, "")
	}
	keys := make([]string, 0, len(settings))
	for key := range settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		line := indent + pbxQuote(key) + " = " + pbxQuote(settings[key]) + ";\n"
		pattern := keyPattern(key)
		if pattern.MatchString(body) {
			body = pattern.ReplaceAllLiteralString(body, line)
			continue
		}
		if !strings.HasPrefix(body, "\n") {
			body = "\n" + body
		}
		body = "\n" + line + body[1:]
	}
	return content[:open+1] + body + content[end-1:], nil
}

func pbxSetBuildSettings(content string, configID string, settings map[string]string, remove []string) (string, error) {
	open, _, ok := pbxBuildSettingsRange(content, configID)
	if !ok {
		return content, fmt.Errorf("build configuration %s has no buildSettings", configID)
	}
	return pbxSetInBlock(content, open, settings, remove)
}

// pbxSetTargetAttributes updates PBXProject TargetAttributes for a target
// (ProvisioningStyle/DevelopmentTeam) when Xcode recorded them; Xcode reads
// ProvisioningStyle alongside CODE_SIGN_STYLE.
func pbxSetTargetAttributes(content string, targetID string, settings map[string]string) (string, error) {
	attributes := regexp.MustCompile(`TargetAttributes = \{`).FindStringIndex(content)
	if attributes == nil {
		return content, nil
	}
	attributesOpen := attributes[1] - 1
	attributesEnd := pbxBlockEnd(content, attributesOpen)
	if attributesEnd < 0 {
		return content, nil
	}
	entry := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(targetID) + `(?:[ \t]*/\*[^*]*\*/)?[ \t]*=[ \t]*\{`).FindStringIndex(content[attributesOpen:attributesEnd])
	if entry == nil {
		return content, nil
	}
	return pbxSetInBlock(content, attributesOpen+entry[1]-1, settings, nil)
}

type iosSigningAssignment struct {
	TargetName  string
	BundleID    string
	ProfileName string
	ProfileUUID string
}

// matchIOSSigningTargets pairs every signable target with a plan target (by
// bundle id, then by target name) and returns the bundle ids that have no
// profile in the plan.
func matchIOSSigningTargets(targets []pbxNativeTarget, plan []storeBuildIOSTarget) (map[string]storeBuildIOSTarget, []string) {
	byBundle := map[string]storeBuildIOSTarget{}
	byName := map[string]storeBuildIOSTarget{}
	for _, target := range plan {
		byBundle[target.BundleID] = target
		byName[target.TargetName] = target
	}
	matched := map[string]storeBuildIOSTarget{}
	missing := []string{}
	for _, target := range targets {
		if !signableProductType(target.ProductType) {
			continue
		}
		if planTarget, ok := byBundle[target.BundleID]; ok && target.BundleID != "" {
			matched[target.ID] = planTarget
			continue
		}
		if planTarget, ok := byName[target.Name]; ok && (target.BundleID == "" || strings.Contains(target.BundleID, "$(")) {
			matched[target.ID] = planTarget
			continue
		}
		label := target.BundleID
		if label == "" {
			label = target.Name
		}
		missing = append(missing, label)
	}
	sort.Strings(missing)
	return matched, missing
}

// patchIOSProjectForStoreSigning applies manual signing to the configuration
// each matched target builds when archiving `configuration`, and the marketing
// version / build number to every configuration of every signable target.
// signingIdentity is the SHA-1 of the distribution certificate imported into
// the job keychain. A name ("Apple Distribution") is ambiguous on hosts that
// hold several distribution certificates for the same team: xcodebuild picks
// whichever it finds first and fails when the profile embeds another one.
func patchIOSProjectForStoreSigning(content string, targets []pbxNativeTarget, matched map[string]storeBuildIOSTarget, configuration string, teamID string, signingIdentity string, version string, buildNumber string) (string, error) {
	var err error
	if signingIdentity == "" {
		signingIdentity = "Apple Distribution"
	}
	for _, target := range targets {
		if !signableProductType(target.ProductType) {
			continue
		}
		configNames := make([]string, 0, len(target.Configurations))
		for name := range target.Configurations {
			configNames = append(configNames, name)
		}
		sort.Strings(configNames)
		for _, name := range configNames {
			content, err = pbxSetBuildSettings(content, target.Configurations[name], map[string]string{
				"MARKETING_VERSION":       version,
				"CURRENT_PROJECT_VERSION": buildNumber,
			}, nil)
			if err != nil {
				return content, fmt.Errorf("target %s %s: %w", target.Name, name, err)
			}
		}
		planTarget, ok := matched[target.ID]
		if !ok {
			continue
		}
		configID := target.configurationID(configuration)
		if configID == "" {
			return content, fmt.Errorf("target %s has no %s configuration", target.Name, configuration)
		}
		content, err = pbxSetBuildSettings(content, configID, map[string]string{
			"CODE_SIGN_STYLE":                   "Manual",
			"DEVELOPMENT_TEAM":                  teamID,
			"CODE_SIGN_IDENTITY":                signingIdentity,
			"CODE_SIGN_IDENTITY[sdk=iphoneos*]": signingIdentity,
			"PROVISIONING_PROFILE_SPECIFIER":    planTarget.ProfileName,
		}, []string{"PROVISIONING_PROFILE", "PROVISIONING_PROFILE_SPECIFIER[sdk=iphoneos*]"})
		if err != nil {
			return content, fmt.Errorf("target %s %s: %w", target.Name, configuration, err)
		}
		content, err = pbxSetTargetAttributes(content, target.ID, map[string]string{
			"ProvisioningStyle": "Manual",
			"DevelopmentTeam":   teamID,
		})
		if err != nil {
			return content, err
		}
	}
	return content, nil
}

// resolveInfoPlistPath turns an INFOPLIST_FILE build setting into a path.
func resolveInfoPlistPath(iosDir string, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, variable := range []string{"$(SRCROOT)", "${SRCROOT}", "$(PROJECT_DIR)", "${PROJECT_DIR}"} {
		value = strings.ReplaceAll(value, variable, iosDir)
	}
	if strings.Contains(value, "$(") || strings.Contains(value, "${") {
		return ""
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(iosDir, value)
	}
	return value
}

// setInfoPlistVersion writes CFBundleShortVersionString/CFBundleVersion into
// an XML Info.plist, adding the keys when absent. Values that reference the
// build settings ($(MARKETING_VERSION)) are left, since those settings are
// patched too. Returns false for a non-XML plist.
func setInfoPlistVersion(path string, version string, buildNumber string) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	content := string(raw)
	if !strings.Contains(content, "<plist") {
		return false, nil
	}
	for key, value := range map[string]string{
		"CFBundleShortVersionString": version,
		"CFBundleVersion":            buildNumber,
	} {
		pattern := regexp.MustCompile(`(<key>` + key + `</key>\s*<string>)([^<]*)(</string>)`)
		if match := pattern.FindStringSubmatch(content); match != nil {
			if strings.Contains(match[2], "$(") {
				continue
			}
			content = pattern.ReplaceAllString(content, "${1}"+html.EscapeString(value)+"${3}")
			continue
		}
		insert := regexp.MustCompile(`(<plist[^>]*>\s*<dict>)`)
		if !insert.MatchString(content) {
			return false, fmt.Errorf("%s has no top-level dict", path)
		}
		content = insert.ReplaceAllString(content, "${1}\n\t<key>"+key+"</key>\n\t<string>"+html.EscapeString(value)+"</string>")
	}
	return true, os.WriteFile(path, []byte(content), 0o644)
}

// iosExportOptionsPlist renders ExportOptions.plist for -exportArchive.
func iosExportOptionsPlist(method string, teamID string, signingCertificate string, profiles map[string]string) []byte {
	var out strings.Builder
	out.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	out.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	out.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	str := func(key, value string) {
		fmt.Fprintf(&out, "\t<key>%s</key>\n\t<string>%s</string>\n", html.EscapeString(key), html.EscapeString(value))
	}
	boolean := func(key string, value bool) {
		tag := "false"
		if value {
			tag = "true"
		}
		fmt.Fprintf(&out, "\t<key>%s</key>\n\t<%s/>\n", key, tag)
	}
	str("destination", "export")
	boolean("manageAppVersionAndBuildNumber", false)
	str("method", method)
	out.WriteString("\t<key>provisioningProfiles</key>\n\t<dict>\n")
	bundleIDs := make([]string, 0, len(profiles))
	for bundleID := range profiles {
		bundleIDs = append(bundleIDs, bundleID)
	}
	sort.Strings(bundleIDs)
	for _, bundleID := range bundleIDs {
		fmt.Fprintf(&out, "\t\t<key>%s</key>\n\t\t<string>%s</string>\n", html.EscapeString(bundleID), html.EscapeString(profiles[bundleID]))
	}
	out.WriteString("\t</dict>\n")
	if signingCertificate != "" {
		str("signingCertificate", signingCertificate)
	}
	str("signingStyle", "manual")
	boolean("stripSwiftSymbols", true)
	str("teamID", teamID)
	boolean("uploadSymbols", true)
	out.WriteString("</dict>\n</plist>\n")
	return []byte(out.String())
}

// iosExportMethod maps the plan to an ExportOptions method.
func iosExportMethod(plan storeBuildPlan) string {
	if plan.IOS != nil {
		switch strings.TrimSpace(plan.IOS.ExportMethod) {
		case "app-store-connect", "release-testing":
			return plan.IOS.ExportMethod
		}
	}
	if plan.Lane == "internal" {
		return "release-testing"
	}
	return "app-store-connect"
}

// storeDeploymentTarget is the highest IPHONEOS_DEPLOYMENT_TARGET among the
// signed targets' archive configuration, or "" when none sets one. Store
// archives pass it to xcodebuild so it also applies to the Pods project:
// CocoaPods keeps each pod's own (often 9.0 or 12.x) target, and Xcode 27
// rejects anything below iOS 15 as an error, failing the archive even though
// the app itself targets 15.1.
func storeDeploymentTarget(content string, targets []pbxNativeTarget, matched map[string]storeBuildIOSTarget, configuration string) string {
	if len(matched) == 0 {
		return ""
	}
	best := ""
	for _, target := range targets {
		if _, ok := matched[target.ID]; !ok {
			continue
		}
		value := strings.Trim(pbxBuildSetting(content, target.Configurations[configuration], "IPHONEOS_DEPLOYMENT_TARGET"), "\"")
		if value != "" && (best == "" || compareVersionStrings(value, best) > 0) {
			best = value
		}
	}
	if best != "" {
		return best
	}
	// Expo projects usually set it at the project level, which every target
	// inherits; this file holds only the app's own project, not Pods.
	for _, match := range pbxDeploymentTargetPattern.FindAllStringSubmatch(content, -1) {
		if best == "" || compareVersionStrings(match[1], best) > 0 {
			best = match[1]
		}
	}
	return best
}

var pbxDeploymentTargetPattern = regexp.MustCompile(`IPHONEOS_DEPLOYMENT_TARGET = "?([0-9][0-9.]*)"?;`)

// compareVersionStrings compares dotted numeric versions ("15.1" < "15.10").
func compareVersionStrings(a, b string) int {
	left, right := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(left) || i < len(right); i++ {
		var x, y int
		if i < len(left) {
			x, _ = strconv.Atoi(left[i])
		}
		if i < len(right) {
			y, _ = strconv.Atoi(right[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
