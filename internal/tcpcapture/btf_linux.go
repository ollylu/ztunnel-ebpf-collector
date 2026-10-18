//go:build linux && amd64

package tcpcapture

import (
	"fmt"
	"github.com/cilium/ebpf/btf"
)

type layout struct{ leader, start, files, fdt, fd, maxfd, inode, mode, ino, private, sk, family, state, kind, net, ns, saddr, daddr, saddr6, daddr6, sport, dport int32 }

func field(s *btf.Spec, typ string, path ...string) (int32, error) {
	var st *btf.Struct
	if e := s.TypeByName(typ, &st); e != nil {
		return 0, e
	}
	var t btf.Type = st
	var off uint32
	for _, name := range path {
		var members []btf.Member
		switch v := btf.UnderlyingType(t).(type) {
		case *btf.Struct:
			members = v.Members
		case *btf.Union:
			members = v.Members
		default:
			return 0, fmt.Errorf("BTF %s not aggregate", name)
		}
		m, ok := member(members, name, 0)
		if !ok {
			return 0, fmt.Errorf("missing BTF %s.%s", typ, name)
		}
		if m.BitfieldSize != 0 || m.Offset%8 != 0 {
			return 0, fmt.Errorf("BTF bitfield unsupported: %s", name)
		}
		off += uint32(m.Offset) / 8
		t = m.Type
	}
	return int32(off), nil
}
func loadLayout() (layout, error) {
	s, e := btf.LoadKernelSpec()
	if e != nil {
		return layout{}, e
	}
	var l layout
	fields := []struct {
		out  *int32
		typ  string
		path []string
	}{
		{&l.leader, "task_struct", []string{"group_leader"}}, {&l.start, "task_struct", []string{"start_boottime"}}, {&l.files, "task_struct", []string{"files"}},
		{&l.fdt, "files_struct", []string{"fdt"}}, {&l.fd, "fdtable", []string{"fd"}}, {&l.maxfd, "fdtable", []string{"max_fds"}},
		{&l.inode, "file", []string{"f_inode"}}, {&l.private, "file", []string{"private_data"}}, {&l.mode, "inode", []string{"i_mode"}}, {&l.ino, "inode", []string{"i_ino"}}, {&l.sk, "socket", []string{"sk"}},
		{&l.family, "sock", []string{"__sk_common", "skc_family"}}, {&l.state, "sock", []string{"__sk_common", "skc_state"}}, {&l.kind, "sock", []string{"sk_type"}},
		{&l.net, "sock", []string{"__sk_common", "skc_net", "net"}}, {&l.ns, "net", []string{"ns", "inum"}},
		{&l.saddr, "sock", []string{"__sk_common", "skc_rcv_saddr"}}, {&l.daddr, "sock", []string{"__sk_common", "skc_daddr"}},
		{&l.saddr6, "sock", []string{"__sk_common", "skc_v6_rcv_saddr"}}, {&l.daddr6, "sock", []string{"__sk_common", "skc_v6_daddr"}},
		{&l.sport, "sock", []string{"__sk_common", "skc_num"}}, {&l.dport, "sock", []string{"__sk_common", "skc_dport"}},
	}
	for _, f := range fields {
		*f.out, e = field(s, f.typ, f.path...)
		if e != nil {
			return l, e
		}
	}
	return l, nil
}

func member(ms []btf.Member, name string, depth int) (btf.Member, bool) {
	if depth > 8 {
		return btf.Member{}, false
	}
	for _, m := range ms {
		if m.Name == name {
			return m, true
		}
	}
	for _, m := range ms {
		if m.Name != "" {
			continue
		}
		var inner []btf.Member
		switch v := btf.UnderlyingType(m.Type).(type) {
		case *btf.Struct:
			inner = v.Members
		case *btf.Union:
			inner = v.Members
		}
		if x, ok := member(inner, name, depth+1); ok {
			x.Offset += m.Offset
			return x, true
		}
	}
	return btf.Member{}, false
}
