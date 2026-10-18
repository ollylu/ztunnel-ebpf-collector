package discovery

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// OutboundListeners proves the observer owns the standard Ambient outbound
// listener in each selected workload's namespace; it never opens a connection.
// Observer descriptors are read once per bounded scan, not once per Pod.
type OutboundScanner struct {
	dir      *os.File
	observer Process
	known    map[string]string // at most one revalidated listener FD per selected Pod
}

func (s *OutboundScanner) Close() {
	if s.dir != nil {
		s.dir.Close()
		s.dir = nil
	}
}
func OutboundListeners(ctx context.Context, root string, observer Process, workers []Process) (map[string]bool, error) {
	s := &OutboundScanner{}
	defer s.Close()
	return s.Scan(ctx, root, observer, workers)
}

// Each pass reads at most 4096 descriptors. Continue the directory on the next
// pass; retained listener proofs are re-read, never treated as permanent ownership.
func (s *OutboundScanner) Scan(ctx context.Context, root string, observer Process, workers []Process) (map[string]bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := observer.Validate(root); err != nil {
		return nil, err
	}
	base := filepath.Join(root, strconv.Itoa(observer.PID), "fdinfo")
	if s.observer.PID != observer.PID || s.observer.StartTime != observer.StartTime || s.observer.NetNS != observer.NetNS {
		s.Close()
		s.known = nil
		s.observer = observer
	}
	if s.dir == nil {
		dir, err := os.Open(base)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, errors.Join(ErrProcessEnded, err)
			}
			return nil, err
		}
		s.dir = dir
	}
	fds, err := s.dir.ReadDir(4096)
	if err != nil {
		s.Close()
		if err != io.EOF {
			return nil, err
		}
	}
	owners := map[string][]string{}
	for _, fd := range fds {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path := filepath.Join(base, fd.Name())
		if inode, e := fdInode(path); e == nil {
			owners[inode] = append(owners[inode], path)
		}
	}
	for _, path := range s.known {
		if inode, e := fdInode(path); e == nil {
			owners[inode] = append(owners[inode], path)
		}
	}
	proofs := map[string]string{}
	anchors := map[string]Process{}
	for _, w := range workers {
		if old, ok := anchors[w.Pod.UID]; ok && (old.NetNS != w.NetNS || old.Pod.IP != w.Pod.IP) {
			return nil, errors.New("ambiguous outbound Pod identity")
		}
		anchors[w.Pod.UID] = w
	}
	if len(anchors) > 32 {
		return nil, errors.New("outbound Pod budget exceeded")
	}
	result := map[string]bool{}
workersLoop:
	for uid, w := range anchors {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if w.Validate(root) != nil {
			continue
		}
		proc := filepath.Join(root, strconv.Itoa(w.PID))
		ns, e := os.Readlink(proc + "/ns/net")
		if e != nil || ns != w.NetNS {
			continue
		}
		for _, table := range []string{"tcp", "tcp6"} {
			b, e := limited(proc+"/net/"+table, 1024*1024)
			if errors.Is(e, os.ErrNotExist) && table == "tcp6" {
				continue
			}
			if e != nil {
				delete(result, uid)
				continue workersLoop
			}
			for i, line := range strings.Split(string(b), "\n") {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if i == 0 || strings.TrimSpace(line) == "" {
					continue
				}
				f := strings.Fields(line)
				if len(f) < 10 {
					delete(result, uid)
					continue workersLoop
				}
				if f[3] != "0A" || len(owners[f[9]]) == 0 {
					continue
				}
				addr, port, e := procEndpoint(f[1])
				if e != nil {
					delete(result, uid)
					continue workersLoop
				}
				if port != 15001 || !addr.IsUnspecified() {
					continue
				}
				for _, path := range owners[f[9]] {
					if inode, e := fdInode(path); e == nil && inode == f[9] {
						result[uid] = true
						proofs[uid] = path
						break
					}
				}
			}
		}
		ns, e = os.Readlink(proc + "/ns/net")
		if e != nil || ns != w.NetNS || w.Validate(root) != nil {
			delete(result, uid)
		}
	}
	if err := observer.Validate(root); err != nil {
		return nil, err
	}
	s.known = map[string]string{}
	for uid, path := range proofs {
		if result[uid] {
			s.known[uid] = path
		}
	}
	return result, ctx.Err()
}
