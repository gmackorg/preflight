package main

import "strings"

func validatePinnedSimulatorJob(options runnerOnceOptions, job apiRunnerJob) error {
	pinned := strings.TrimSpace(options.simulatorUDID)
	provider := strings.TrimSpace(job.Payload.ProviderIdentity)
	if provider == "" {
		provider = strings.TrimSpace(job.TargetID)
	}
	if pinned == "" || jobPlatform(job) != "ios" || isPhysicalIOSDeviceDiscovery(job) {
		return nil
	}
	switch job.Kind {
	case "simulator.open", "maestro.run", "dev_session.start", "dev_session.open", "eas.build.dev":
		if !strings.EqualFold(pinned, provider) {
			return sourceBindingMismatch("simulatorUDID", pinned, provider)
		}
	}
	return nil
}
