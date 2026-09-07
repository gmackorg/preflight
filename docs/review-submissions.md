# Selecting a build for App Review

App Review submission requires an explicit App Store Connect build ID, marketing version, and build number. Preflight checks the selected build's app relationship, iOS version, build number, processing state (`VALID`) and expiry before submitting it. It never picks the first or latest available binary.

List the app's available builds, then submit the selected one:

```sh
preflight apps submit-for-review checkout --list-builds
preflight apps submit-for-review checkout --asc-build-id ASC_BUILD_ID --version 2.0 --build-number 42
```

Submission keeps a manual release hold, including when an editable App Store version already exists. The existing readiness and workspace authorization checks still apply. A completed request means submitted for review, not approved or released.

Fleet submission remains a dry run unless `--fire` is specified. Supply explicit selections keyed by Preflight app ID:

```json
{
  "pf_app_checkout": {
    "ascBuildId": "ASC_BUILD_ID",
    "version": "2.0",
    "buildNumber": "42"
  }
}
```

```sh
preflight apps submit-for-review --all
preflight apps submit-for-review --all --fire --selections-file selections.json
```

Every ready app needs a complete selection before the CLI sends the first submission. The server revalidates each selected binary immediately before its submission. App Review supports iOS; Android uses its separate release workflow.
