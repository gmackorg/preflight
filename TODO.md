
## Replace ngrok with Tailscale for device-lane dev sessions (P1, proposed 2026-07-20)
ngrok is the flakiest link in the development lane: one-agent-session limit (concurrent
tunnels kill each other), "remote gone away"/"session closed" flakes, and the tunnel URL
never reaches non-TTY logs (we scrape Metro's manifest hostUri as a workaround). The
device is already on the tailnet, so Metro is directly reachable without any tunnel.

Proposal: add `--host-mode tailscale` to `preflight runner once`:
- start expo normally (Metro binds all interfaces)
- advertise `http://$(tailscale ip -4):<metro-port>` (or MagicDNS host) in the
  dev-session URL/QR instead of an ngrok URL
- advertise the `expo.dev_server.tunnel` capability (same contract: remotely
  reachable dev server), so server-side claim routing works unchanged
Then reprovision labtop-tunnel as labtop-tailscale and delete the ngrok/manifest-scrape
path (expoTunnelDevServerURLFromManifest and friends). Effort: S with CC.

## No CLI command to trigger a production store build → TestFlight (P1, proposed 2026-08-12)

There is no way from the `preflight` CLI to kick a fresh **production store build**
(and its TestFlight distribute) for an app. This blocked a real request: get a new
`@playtrek/expo` build into TestFlight with recent commits. Everything on the
build-machine side was ready and it still couldn't be done from the CLI.

What exists today (and why none of it triggers a store build):
- `prove-app` is the only workflow-creating CLI verb, and it's **dev/sim only**
  (`lane: simulator|development`, `build-strategy: local|eas development` — see the
  usage block in main.go and `proveAppOptions{lane: "simulator"}`). It cannot
  create a production/store build workflow.
- `preflight runner once` is **reactive** — it only claims server-queued jobs. When
  an app's pipeline is already at `store_build ✓ / testflight ✓ done`, the runner
  reports `no runner jobs available`. There's no CLI to *enqueue* the build it would
  execute.
- Runner **refuses** the production profile unless `runningInCI()` (main.go
  `handleEASBuildDevJob`, `isProductionBuildProfile` + the `production_build_ci_only`
  setup-required branch). Its guidance is `gh workflow run mobile-production.yml` —
  i.e. the sanctioned path is a **repo-side CI workflow** that many apps don't have
  (playtrek has no `.forgejo`/`.github` mobile-production workflow; it's a Forgejo
  repo, not GitHub, so `gh` doesn't apply either).
- `eas.submit` (the one-click distribute) needs an **already-finished `easBuildID`**;
  there's no CLI to produce that build.
- Net: the store-build enqueue is **server-side only** (Preflight web/API/fleet). An
  operator with a fully-provisioned build machine (repo cloned + `pnpm install`, EAS
  authed, ASC provider connected, runner installed, `CI=1`) still has no CLI verb to
  say "build @playtrek/expo production and push to TestFlight."

Repro (2026-08-12): gmacko-mini fully provisioned (preflight binary installed,
`eas whoami` = mackieg, `~/playtrek-build` at HEAD 9008144 + installed, `CI=1`).
`preflight runner once --workspace-root ~/playtrek-build` → `no runner jobs
available`. No CLI path to enqueue a fresh `@playtrek/expo` store build.

Proposal: add a CLI verb to enqueue a production store build (+ optional
auto-distribute), e.g.:
- `preflight apps build <app> --profile production [--platform ios] [--distribute]`
  — creates the store_build workflow the server would otherwise create, so a
  runner (in CI mode) or CI executes it, then chains the `eas.submit` distribute to
  TestFlight; **or**
- extend `prove-app` with a `--lane store|testflight` (production profile) that
  emits a store-build workflow instead of a dev/sim one.
For apps without a repo-side `mobile-production` CI workflow, sanction the
`runner + CI=1` local-build path (it already works past the
`production_build_ci_only` gate when `CI` is set) as a first-class option so the
CLI can drive the whole build→submit on a provisioned build machine.
Also consider: `preflight apps status` should surface a "rebuild" next-action when a
finished app needs a fresh build, and a matching CLI verb to trigger it — today
`store_build ✓ done` gives operators no CLI affordance to request a new one.
Effort: M (server workflow-create endpoint + CLI verb + wire the runner CI path).
