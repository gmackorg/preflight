package main

import "testing"

// The agent's --host-mode says what a host CAN do; the job says what it NEEDS.
//
// Reading the agent flag for every session made a tunnel-capable runner start
// `expo start --host tunnel` for simulator work too, so the gate waited on
// ngrok before Metro answered /status and failed with metro_start_timeout.
// Switching one Mac to tunnel mode for a device build broke its simulator gates.
func TestExpoHostArgForJob(t *testing.T) {
	tunnelJob := apiRunnerJob{}
	tunnelJob.Payload.NetworkPolicy.TunnelRequired = true
	plainJob := apiRunnerJob{}

	cases := []struct {
		name     string
		hostMode string
		job      apiRunnerJob
		want     string
	}{
		{"device session on a tunnel host tunnels", "tunnel", tunnelJob, "tunnel"},
		{"device session on a lan host still tunnels", "lan", tunnelJob, "tunnel"},
		// Tailscale reaches the device over the tailnet, so it never shells out
		// to ngrok even when a tunnel is required.
		{"device session on a tailscale host uses lan", "tailscale", tunnelJob, "lan"},

		{"simulator session on a tunnel host stays lan", "tunnel", plainJob, "lan"},
		{"simulator session on a lan host stays lan", "lan", plainJob, "lan"},
		{"simulator session on a tailscale host stays lan", "tailscale", plainJob, "lan"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := expoHostArgForJob(c.hostMode, c.job); got != c.want {
				t.Fatalf("expoHostArgForJob(%q) = %q, want %q", c.hostMode, got, c.want)
			}
		})
	}
}
