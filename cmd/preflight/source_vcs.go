package main

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type sourceRepositoryState struct {
	remote  string
	branch  string
	commit  string
	changed []string
}

type jjSourceCommit struct {
	id      string
	parents []string
	empty   bool
}

var sourceSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
var safeRepositoryName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func jjOnlyWorkspace(root string) bool {
	_, jjErr := os.Stat(filepath.Join(root, ".jj"))
	_, gitErr := os.Stat(filepath.Join(root, ".git"))
	return jjErr == nil && os.IsNotExist(gitErr)
}

func jjSourceOutput(root string, args ...string) (string, error) {
	command := exec.Command("jj", append([]string{"--ignore-working-copy", "--color=never", "--no-pager"}, args...)...)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("could not inspect jj source")
	}
	return strings.TrimSpace(string(output)), nil
}

func jjSourceRevision(root string, revision string) (jjSourceCommit, error) {
	output, err := jjSourceOutput(root, "log", "--no-graph", "-r", revision, "-T", `commit_id ++ "\n" ++ parents.map(|p| p.commit_id()).join(" ") ++ "\n" ++ if(empty, "true", "false") ++ "\n" ++ if(conflict, "true", "false")`)
	if err != nil {
		return jjSourceCommit{}, err
	}
	lines := strings.Split(output, "\n")
	if len(lines) != 4 || !sourceSHA.MatchString(lines[0]) || lines[3] != "false" {
		return jjSourceCommit{}, fmt.Errorf("jj source is conflicted or could not be resolved uniquely")
	}
	return jjSourceCommit{id: lines[0], parents: strings.Fields(lines[1]), empty: lines[2] == "true"}, nil
}

func jjSourceRemotes(root string) (map[string]string, []string, error) {
	output, err := jjSourceOutput(root, "git", "remote", "list")
	if err != nil {
		return nil, nil, err
	}
	remotes := make(map[string]string)
	var names []string
	for _, line := range strings.Split(output, "\n") {
		name, remote, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		remotes[name] = strings.TrimSpace(remote)
		names = append(names, name)
	}
	sort.Strings(names)
	if _, ok := remotes["origin"]; ok {
		filtered := []string{"origin"}
		for _, name := range names {
			if name != "origin" {
				filtered = append(filtered, name)
			}
		}
		names = filtered
	}
	return remotes, names, nil
}

func jjCommitOnRemote(root, remoteName, sha string) bool {
	if !sourceSHA.MatchString(sha) {
		return false
	}
	revset := sha + " & ancestors(remote_bookmarks(remote=" + strconv.Quote(remoteName) + "))"
	output, err := jjSourceOutput(root, "log", "--no-graph", "-r", revset, "-T", "commit_id")
	return err == nil && output == sha
}

func readJJSourceRepository(root string) (sourceRepositoryState, error) {
	// Unlike --ignore-working-copy, status snapshots tracked AND newly added
	// files before reading @. This only updates this workspace's jj snapshot;
	// no commits, bookmarks or files are discarded. Skipped files are unknown
	// source, so warnings (including oversized untracked files) fail closed.
	command := exec.Command("jj", "--color=never", "--no-pager", "status")
	command.Dir = root
	var warnings bytes.Buffer
	var status bytes.Buffer
	command.Stderr = &warnings
	command.Stdout = &status
	if err := command.Run(); err != nil || warnings.Len() != 0 || strings.Contains(status.String(), "Untracked paths:") {
		return sourceRepositoryState{}, fmt.Errorf("jj working copy could not be completely snapshotted")
	}
	current, err := jjSourceRevision(root, "@")
	if err != nil {
		return sourceRepositoryState{}, err
	}
	remotes, names, err := jjSourceRemotes(root)
	if err != nil {
		return sourceRepositoryState{}, err
	}
	selected := current
	selectedRemote := ""
	// Empty disposable working-copy children do not have a published SHA.
	// Drop those only while there is exactly one parent, stopping at the first
	// published commit, including a published empty merge commit.
	for {
		for _, name := range names {
			if jjCommitOnRemote(root, name, selected.id) {
				selectedRemote = name
				break
			}
		}
		if selectedRemote != "" || !selected.empty || len(selected.parents) != 1 {
			break
		}
		selected, err = jjSourceRevision(root, selected.parents[0])
		if err != nil {
			return sourceRepositoryState{}, err
		}
	}
	if selectedRemote == "" && len(names) > 0 {
		selectedRemote = names[0]
	}
	state := sourceRepositoryState{remote: remotes[selectedRemote], commit: selected.id}
	if selectedRemote != "" {
		branches, branchErr := jjSourceOutput(root, "bookmark", "list", "--remote", "exact:"+selectedRemote, "--revisions", selected.id, "-T", `if(remote, name ++ "\n", "")`)
		if branchErr != nil {
			return sourceRepositoryState{}, branchErr
		}
		if lines := strings.Fields(branches); len(lines) > 0 {
			state.branch = lines[0]
		}
	}
	// A nonempty unpublished @ is local source. Record its actual SHA and
	// compare against its parents; --ci then refuses it instead of quietly
	// building an older published revision as though it included the edits.
	from := selected.id
	if !jjCommitOnRemote(root, selectedRemote, selected.id) && !selected.empty {
		if len(selected.parents) != 1 {
			return sourceRepositoryState{}, fmt.Errorf("unpublished jj merge source cannot be resolved safely")
		}
		from = selected.parents[0]
	}
	changed, err := jjSourceOutput(root, "diff", "--from", from, "--to", current.id, "--name-only")
	if err != nil {
		return sourceRepositoryState{}, err
	}
	for _, path := range strings.Split(changed, "\n") {
		if path != "" {
			state.changed = append(state.changed, filepath.ToSlash(path))
		}
	}
	return state, nil
}

func readSourceRepository(root string) (sourceRepositoryState, error) {
	if jjOnlyWorkspace(root) {
		return readJJSourceRepository(root)
	}
	remote, branch, commit := sourceBindingGitIdentity(root)
	return sourceRepositoryState{remote: remote, branch: branch, commit: commit, changed: gitChangedFiles(root)}, nil
}

func sourceCommitIsOnRemote(root, remoteURL, sha string) bool {
	if !sourceSHA.MatchString(sha) {
		return false
	}
	if jjOnlyWorkspace(root) {
		remotes, names, err := jjSourceRemotes(root)
		if err != nil {
			return false
		}
		for _, name := range names {
			if remotes[name] == remoteURL && jjCommitOnRemote(root, name, sha) {
				return true
			}
		}
		return false
	}
	remotes, err := gitOutput(root, "remote")
	if err != nil {
		return false
	}
	for _, name := range strings.Fields(remotes) {
		value, err := gitOutput(root, "remote", "get-url", name)
		if err != nil || value != remoteURL {
			continue
		}
		refs, err := gitOutput(root, "for-each-ref", "--contains="+sha, "--format=%(refname)", "refs/remotes/"+name+"/")
		if err == nil && refs != "" {
			return true
		}
	}
	return false
}

func ciRepositoryName(workspaceRoot, remote string) (string, error) {
	path := remote
	if strings.Contains(remote, "%") {
		return "", fmt.Errorf("remote has no safe repository basename")
	}
	if strings.Contains(remote, "://") {
		parsed, err := url.Parse(remote)
		if err != nil {
			return "", fmt.Errorf("could not resolve repository name")
		}
		path = parsed.Path
	} else if colon := strings.Index(remote, ":"); colon >= 0 {
		path = remote[colon+1:]
	}
	// A remote root or encoded path delimiter is not a repository basename.
	if strings.HasSuffix(path, "/") || strings.ContainsAny(path, "%\\") {
		return "", fmt.Errorf("remote has no safe repository basename")
	}
	name := strings.TrimSuffix(filepath.Base(path), ".git")
	if !safeRepositoryName.MatchString(name) || name == "." || name == ".." {
		return "", fmt.Errorf("remote has no safe repository basename")
	}
	return name, nil
}
