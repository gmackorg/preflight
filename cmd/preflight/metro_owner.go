package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// A live app-local pid handle does not prove ownership of an arbitrary healthy
// port. npx can remain alive on one port while another app listens on the port
// requested by a new workflow. Require the listener to belong to the recorded
// process tree and to run in this app directory. Unverifiable owners fail closed;
// this check never stops another workflow's server.
func metroListenerOwnedByApp(appDir string, ownerPID int, statusURL string) bool {
	u, err := url.Parse(statusURL)
	if err != nil || u.Scheme != "http" || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 || port > 65535 {
		return false
	}
	appPath, err := filepath.EvalSymlinks(appDir)
	if err != nil {
		return false
	}
	parents := metroProcessParents()
	listeners := metroListenerPIDs(port)
	if len(listeners) == 0 {
		return false
	}
	// localhost may resolve to either loopback family. When multiple processes
	// share a port on different addresses, require every observable listener to
	// belong to this app instead of accepting one owned IPv4 listener while the
	// HTTP probe reaches another app's IPv6 listener.
	for _, pid := range listeners {
		if !metroProcessDescendsFrom(pid, ownerPID, parents) {
			return false
		}
		cwd, err := metroProcessCwd(pid)
		if err != nil {
			return false
		}
		cwd, err = filepath.EvalSymlinks(cwd)
		if err != nil || cwd != appPath {
			return false
		}
	}
	return true
}

func metroProcessOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

func metroProcessParents() map[int]int {
	parents := make(map[int]int)
	out, err := metroProcessOutput("ps", "-eo", "pid=,ppid=")
	if err != nil {
		return parents
	}
	for _, row := range strings.Split(string(out), "\n") {
		fields := strings.Fields(row)
		if len(fields) != 2 {
			continue
		}
		pid, pidErr := strconv.Atoi(fields[0])
		parent, parentErr := strconv.Atoi(fields[1])
		if pidErr == nil && parentErr == nil && pid > 0 {
			parents[pid] = parent
		}
	}
	return parents
}

func metroProcessDescendsFrom(pid, owner int, parents map[int]int) bool {
	for remaining := len(parents) + 1; pid > 0 && remaining > 0; remaining-- {
		if pid == owner {
			return true
		}
		pid = parents[pid]
	}
	return false
}

func metroProcessCwd(pid int) (string, error) {
	if runtime.GOOS == "linux" {
		return os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	}
	out, err := metroProcessOutput("lsof", "-a", "-p", strconv.Itoa(pid), "-d", "cwd", "-Fn")
	if err != nil {
		return "", err
	}
	for _, row := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(row, "n/") {
			return strings.TrimPrefix(row, "n"), nil
		}
	}
	return "", fmt.Errorf("process %d has no observable working directory", pid)
}

func metroListenerPIDs(port int) []int {
	if runtime.GOOS == "linux" {
		return linuxMetroListenerPIDs(port)
	}
	out, err := metroProcessOutput("lsof", "-nP", "-a", "-iTCP:"+strconv.Itoa(port), "-sTCP:LISTEN", "-Fp")
	if err != nil {
		return nil
	}
	var pids []int
	for _, row := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(row, "p") {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimPrefix(row, "p"))
		if err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids
}

// Linux runners do not universally ship lsof. Match LISTEN socket inodes from
// procfs to process file descriptors instead of depending on another CLI tool.
func linuxMetroListenerPIDs(port int) []int {
	inodes := make(map[string]bool)
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		content, err := os.ReadFile(table)
		if err != nil {
			continue
		}
		for _, row := range strings.Split(string(content), "\n") {
			fields := strings.Fields(row)
			if len(fields) < 10 || fields[3] != "0A" {
				continue
			}
			_, hexPort, found := strings.Cut(fields[1], ":")
			parsed, err := strconv.ParseInt(hexPort, 16, 32)
			if found && err == nil && parsed == int64(port) {
				inodes["socket:["+fields[9]+"]"] = true
			}
		}
	}
	if len(inodes) == 0 {
		return nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err == nil && inodes[target] {
				pids = append(pids, pid)
				break
			}
		}
	}
	return pids
}
