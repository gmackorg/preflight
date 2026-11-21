
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

## Store builds from the CLI (resolved by PREFLT-66)

`preflight build store --app <id> --platform ios|android --lane internal|beta|store
[--wait]` queues a `store.build` job on the control plane; a runner builds with
`expo prebuild` + `xcodebuild`/Gradle, signs with the vault credentials and uploads
to TestFlight or Google Play (`store.upload`). The hosted-build submit path and
the CI-only production gate are gone.

Follow-ups:
- `credentials import-eas --expo-token-ref <id>` sends `expoTokenSecretReferenceId`,
  but the import routes still pick the workspace's active Expo token by provider
  and purpose. Teach the routes to honour the reference (or drop the flag).
- `build store --wait` polls `/api/v1/apps/<id>/builds` (the only build read the
  control plane exposes). A `GET /api/preflight/v1/apps/<id>/store-builds/<buildId>`
  would avoid listing.
- `preflight apps status` could offer a "rebuild" next action that runs
  `build store` for a finished app.
