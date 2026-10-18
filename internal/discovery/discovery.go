// Package discovery resolves Kubernetes container identities to host processes.
// It never opens a container-runtime socket or relies on process names alone.
package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Pod struct{ UID, Name, Namespace, Node, IP, ContainerID string }
type Process struct {
	PID       int
	StartTime uint64
	NetNS     string
	Pod       Pod
}

func limited(path string, n int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, n+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > n {
		return nil, errors.New("metadata exceeds limit")
	}
	return b, nil
}
func StartTime(root string, pid int) (uint64, error) {
	b, e := limited(filepath.Join(root, strconv.Itoa(pid), "stat"), 4096)
	if e != nil {
		return 0, e
	}
	// comm may contain spaces and ')'; fields after the final ')' start at field 3.
	at := strings.LastIndexByte(string(b), ')')
	if at < 0 {
		return 0, errors.New("invalid proc stat")
	}
	f := strings.Fields(string(b[at+1:]))
	if len(f) < 20 {
		return 0, errors.New("invalid or dead process")
	}
	if f[0] == "Z" || f[0] == "X" {
		return 0, ErrProcessEnded
	}
	return strconv.ParseUint(f[19], 10, 64)
}
func containerID(s string) string {
	id, ok := strings.CutPrefix(s, "containerd://")
	if !ok || len(id) != 64 {
		return ""
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	return id
}
func matches(cgroup string, p Pod) bool {
	id := containerID(p.ContainerID)
	if id == "" || p.UID == "" {
		return false
	}
	for _, line := range strings.Split(cgroup, "\n") {
		f := strings.SplitN(line, ":", 3)
		if len(f) != 3 {
			continue
		}
		hasPod, hasID := false, false
		for _, seg := range strings.Split(f[2], "/") {
			if seg == id || seg == "cri-containerd-"+id+".scope" {
				hasID = true
			}
			seg = strings.ReplaceAll(strings.TrimSuffix(seg, ".slice"), "_", "-")
			if seg == "pod"+p.UID || strings.HasSuffix(seg, "-pod"+p.UID) {
				hasPod = true
			}
		}
		if hasPod && hasID {
			return true
		}
	}
	return false
}
func Find(ctx context.Context, root string, pods []Pod, node string) ([]Process, error) {
	return find(ctx, root, pods, node, "ztunnel")
}
func FindWorkload(ctx context.Context, root string, pods []Pod, node string) ([]Process, error) {
	return find(ctx, root, pods, node, "")
}
func find(ctx context.Context, root string, pods []Pod, node, executable string) ([]Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(4097)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > 4096 {
		return nil, errors.New("proc scan budget exceeded")
	}
	var out []Process
	for _, ent := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid <= 0 || !ent.IsDir() {
			continue
		}
		base := filepath.Join(root, ent.Name())
		start, err := StartTime(root, pid)
		if err != nil {
			continue
		}
		cg, err := limited(base+"/cgroup", 16384)
		if err != nil {
			continue
		}
		for _, p := range pods {
			if p.Node != node || !matches(string(cg), p) {
				continue
			}
			exe, err := os.Readlink(base + "/exe")
			if err != nil || (executable != "" && filepath.Base(exe) != executable) {
				continue
			}
			ns, err := os.Readlink(base + "/ns/net")
			if err != nil || !strings.HasPrefix(ns, "net:[") {
				continue
			}
			again, err := StartTime(root, pid)
			if err != nil || again != start {
				continue
			}
			out = append(out, Process{PID: pid, StartTime: start, NetNS: ns, Pod: p})
			break
		}
	}
	return out, nil
}

// ReadPods accepts a bounded Kubernetes PodList snapshot, never request payloads.
// Callers must refresh snapshots; capture is bounded and rechecks target lifetimes.
func ReadPods(r io.Reader) ([]Pod, error) {
	var list struct {
		Items []struct {
			Metadata struct{ UID, Name, Namespace string }
			Spec     struct{ NodeName string }
			Status   struct {
				PodIP, Phase      string
				ContainerStatuses []struct {
					Name, ContainerID string
					State             struct{ Running *json.RawMessage }
				}
			}
		}
	}
	b, err := io.ReadAll(io.LimitReader(r, 4*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 4*1024*1024 {
		return nil, errors.New("pod metadata budget exceeded")
	}
	if err = json.Unmarshal(b, &list); err != nil {
		return nil, errors.New("invalid pod metadata")
	}
	if len(list.Items) > 2048 {
		return nil, errors.New("pod count exceeds budget")
	}
	var out []Pod
	for _, p := range list.Items {
		if p.Status.Phase != "Running" {
			continue
		}
		for _, c := range p.Status.ContainerStatuses {
			if c.State.Running == nil {
				continue
			}
			out = append(out, Pod{p.Metadata.UID, p.Metadata.Name, p.Metadata.Namespace, p.Spec.NodeName, p.Status.PodIP, c.ContainerID})
		}
	}
	return out, nil
}

// ErrProcessEnded denotes a proven identity change, not an arbitrary proc I/O error.
var ErrProcessEnded = errors.New("process generation ended")

func (p Process) Validate(root string) error {
	s, e := StartTime(root, p.PID)
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			return errors.Join(ErrProcessEnded, e)
		}
		return e
	}
	if s != p.StartTime {
		return ErrProcessEnded
	}
	base := filepath.Join(root, strconv.Itoa(p.PID))
	b, e := limited(base+"/cgroup", 16384)
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			return errors.Join(ErrProcessEnded, e)
		}
		return e
	}
	if !matches(string(b), p.Pod) {
		return ErrProcessEnded
	}
	ns, e := os.Readlink(base + "/ns/net")
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			return errors.Join(ErrProcessEnded, e)
		}
		return e
	}
	if ns != p.NetNS {
		return ErrProcessEnded
	}
	return nil
}
