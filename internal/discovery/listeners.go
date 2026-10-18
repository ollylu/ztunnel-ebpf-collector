package discovery

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ListeningPorts reads listener metadata only. A socket must be held by a
// verified process in this Pod, not merely present in its shared network ns
// (ztunnel also holds sockets in that ns). No probes or connection attempts.
func ListeningPorts(ctx context.Context, root string, processes []Process) ([]uint16, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(processes) == 0 {
		return nil, errors.New("no verified listener owner")
	}
	anchor := processes[0]
	ip, err := netip.ParseAddr(anchor.Pod.IP)
	if err != nil || !ip.Is4() {
		return nil, errors.New("listener discovery requires IPv4 Pod")
	}
	// Recheck each fd after reading the socket tables; a disappearing/reused fd
	// must not lend ownership to an unrelated socket in the namespace.
	owners := map[string][]string{}
	entries := 0
	for _, p := range processes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if p.Pod.UID != anchor.Pod.UID || p.Pod.IP != anchor.Pod.IP || p.NetNS != anchor.NetNS {
			return nil, errors.New("ambiguous listener Pod identity")
		}
		if err := p.Validate(root); err != nil {
			return nil, err
		}
		base := filepath.Join(root, strconv.Itoa(p.PID))
		ns, e := os.Readlink(base + "/ns/net")
		if e != nil || ns != p.NetNS {
			return nil, errors.New("listener network namespace changed")
		}
		dir, e := os.Open(base + "/fdinfo")
		if e != nil {
			return nil, e
		}
		fds, e := dir.ReadDir(4097 - entries)
		dir.Close()
		if e != nil && e != io.EOF {
			return nil, e
		}
		entries += len(fds)
		if entries > 4096 {
			return nil, errors.New("listener fd budget exceeded")
		}
		for _, fd := range fds {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			path := base + "/fdinfo/" + fd.Name()
			inode, e := fdInode(path)
			if e == nil {
				owners[inode] = append(owners[inode], path)
			}
		}
	}
	ports := map[uint16]bool{}
	for _, table := range []string{"tcp", "tcp6"} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		b, e := limited(filepath.Join(root, strconv.Itoa(anchor.PID), "net", table), 1024*1024)
		if errors.Is(e, os.ErrNotExist) && table == "tcp6" {
			continue
		}
		if e != nil {
			return nil, e
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
				return nil, errors.New("invalid TCP listener table")
			}
			if f[3] != "0A" || len(owners[f[9]]) == 0 {
				continue
			}
			addr, port, e := procEndpoint(f[1])
			if e != nil {
				return nil, e
			}
			if !addr.IsUnspecified() && addr.Unmap() != ip {
				continue
			} // exclude loopback-only and other addresses
			stillOwned := false
			for _, path := range owners[f[9]] {
				inode, e := fdInode(path)
				if e == nil && inode == f[9] {
					stillOwned = true
					break
				}
			}
			if !stillOwned {
				continue
			}
			ports[port] = true
			if len(ports) > 32 {
				return nil, errors.New("listener port budget exceeded")
			}
		}
	}
	for _, p := range processes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := p.Validate(root); err != nil {
			return nil, err
		}
	}
	out := make([]uint16, 0, len(ports))
	for port := range ports {
		out = append(out, port)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// /proc/net/tcp{,6} formats addresses as native-endian 32-bit words on amd64.
func procEndpoint(text string) (netip.Addr, uint16, error) {
	host, port, ok := strings.Cut(text, ":")
	n, err := strconv.ParseUint(port, 16, 16)
	if !ok || err != nil || n == 0 || (len(host) != 8 && len(host) != 32) {
		return netip.Addr{}, 0, errors.New("invalid proc endpoint")
	}
	var b [16]byte
	for i := 0; i < len(host); i += 8 {
		word, e := strconv.ParseUint(host[i:i+8], 16, 32)
		if e != nil {
			return netip.Addr{}, 0, fmt.Errorf("invalid listener address")
		}
		binary.LittleEndian.PutUint32(b[i/2:i/2+4], uint32(word))
	}
	if len(host) == 8 {
		return netip.AddrFrom4([4]byte(b[:4])), uint16(n), nil
	}
	return netip.AddrFrom16(b), uint16(n), nil
}

// fdinfo is traversable for non-root workload owners with the existing
// SYS_PTRACE permission; /proc/PID/fd is mode 0500 and would need DAC bypass.
func fdInode(path string) (string, error) {
	b, err := limited(path, 4096)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "ino:" {
			n, e := strconv.ParseUint(f[1], 10, 64)
			if e == nil && n != 0 {
				return f[1], nil
			}
		}
	}
	return "", errors.New("fd inode unavailable")
}
