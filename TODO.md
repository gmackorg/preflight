
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
