//go:build linux && amd64

package tcpcapture

import (
	"github.com/cilium/ebpf/asm"
)

const payload = 128
const maxData = 16 * 1024

// Guard capacity lets the verifier bound offset and read size independently.
// Logical payload remains capped at maxData; the guard is never emitted.
const valueSize = payload + 2*maxData

// Instructions observe one process generation and a bounded exact endpoint map.
func programs(c Config, l layout, inflight, zero, ring, loss, targets, suppressed int) (asm.Instructions, asm.Instructions) {
	var a asm.Instructions
	add := func(xs ...asm.Instruction) { a = append(a, xs...) }
	read := func(dst asm.Register, base asm.Register, off int32, size asm.Size) {
		add(asm.Mov.Reg(asm.R3, base), asm.Add.Imm(asm.R3, off), asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -16), asm.Mov.Imm(asm.R2, int32(size.Sizeof())), asm.FnProbeReadKernel.Call(), asm.JNE.Imm(asm.R0, 0, "cleanup"), asm.LoadMem(dst, asm.RFP, -16, size))
	}
	lookup := func(fd int) {
		add(asm.LoadMapPtr(asm.R1, fd), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8), asm.FnMapLookupElem.Call())
	}
	add(asm.Mov.Reg(asm.R6, asm.R1), asm.FnGetCurrentPidTgid.Call(), asm.Mov.Reg(asm.R7, asm.R0), asm.RSh.Imm(asm.R0, 32), asm.JNE.Imm(asm.R0, int32(c.PID), "exit"), asm.StoreMem(asm.RFP, -8, asm.R7, asm.DWord))
	add(asm.LoadMem(asm.R0, asm.R6, 8, asm.DWord)) // syscall id
	for _, id := range []int32{0, 1, 3, 19, 20, 42, 44, 45, 46, 47, 55} {
		add(asm.JEq.Imm(asm.R0, id, "selected"))
	}
	add(asm.Ja.Label("exit"))
	add(asm.FnGetCurrentTask.Call().WithSymbol("selected"), asm.Mov.Reg(asm.R9, asm.R0))
	read(asm.R9, asm.R9, l.leader, asm.DWord)
	read(asm.R9, asm.R9, l.start, asm.DWord)
	add(asm.Div.Imm(asm.R9, 10000000), asm.LoadImm(asm.R0, int64(c.StartTime), asm.DWord), asm.JNE.Reg(asm.R9, asm.R0, "exit")) // amd64 USER_HZ=100
	// Resolve small socket metadata on stack first. Unselected traffic never
	// allocates or clears the valueSize-byte payload map entry. Scratch ends at -152.
	add(asm.Mov.Reg(asm.R8, asm.RFP), asm.Add.Imm(asm.R8, -384))
	for off := int16(0); off < 160; off += 8 {
		add(asm.Mov.Imm(asm.R0, 0), asm.StoreMem(asm.R8, off, asm.R0, asm.DWord))
	}
	add(asm.LoadMem(asm.R0, asm.R6, 16, asm.DWord), asm.JGT.Imm(asm.R0, 0x7fffffff, "cleanup"), asm.StoreMem(asm.R8, 12, asm.R0, asm.Word))
	add(asm.FnGetCurrentTask.Call(), asm.Mov.Reg(asm.R9, asm.R0))
	read(asm.R9, asm.R9, l.files, asm.DWord)
	read(asm.R9, asm.R9, l.fdt, asm.DWord)
	read(asm.R0, asm.R9, l.maxfd, asm.Word)
	add(asm.LoadMem(asm.R1, asm.R8, 12, asm.Word), asm.JGE.Reg(asm.R1, asm.R0, "cleanup"))
	read(asm.R9, asm.R9, l.fd, asm.DWord)
	add(asm.LoadMem(asm.R0, asm.R8, 12, asm.Word), asm.LSh.Imm(asm.R0, 3), asm.Add.Reg(asm.R9, asm.R0))
	read(asm.R9, asm.R9, 0, asm.DWord)
	add(asm.StoreMem(asm.RFP, -32, asm.R9, asm.DWord))
	read(asm.R9, asm.R9, l.inode, asm.DWord)
	read(asm.R0, asm.R9, l.mode, asm.Half)
	add(asm.And.Imm(asm.R0, 0xf000), asm.JNE.Imm(asm.R0, 0xc000, "cleanup"))
	read(asm.R0, asm.R9, l.ino, asm.DWord)
	add(asm.StoreMem(asm.R8, 0, asm.R0, asm.DWord), asm.LoadMem(asm.R9, asm.RFP, -32, asm.DWord))
	read(asm.R9, asm.R9, l.private, asm.DWord)
	read(asm.R9, asm.R9, l.sk, asm.DWord)
	read(asm.R0, asm.R9, l.kind, asm.Half)
	add(asm.JNE.Imm(asm.R0, 1, "cleanup"))
	read(asm.R0, asm.R9, l.sport, asm.Half)
	add(asm.StoreMem(asm.R8, 32, asm.R0, asm.Half))
	read(asm.R0, asm.R9, l.net, asm.DWord)
	read(asm.R0, asm.R0, l.ns, asm.Word)
	add(asm.StoreMem(asm.R8, 8, asm.R0, asm.Word))
	// Any admitted socket may lose addresses/ports on reset. Recover its
	// identity before address-family validation for close or buffered TCP_CLOSE.
	add(asm.LoadMem(asm.R0, asm.R6, 8, asm.DWord), asm.JEq.Imm(asm.R0, 3, "recover_identity"), asm.JEq.Imm(asm.R0, 42, "normal_target"), asm.LoadMem(asm.R0, asm.R8, 32, asm.Half), asm.JNE.Imm(asm.R0, 0, "normal_target"))
	// TCP_CLOSE=7 (include/net/tcp_states.h). Buffered data can remain readable
	// after reset cleared skc_num; only an already admitted socket can recover.
	read(asm.R0, asm.R9, l.state, asm.Byte)
	add(asm.JNE.Imm(asm.R0, 7, "normal_target"), asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("recover_identity"))
	a = append(a, stableSuppressionLookup(suppressed)...)
	add(asm.JEq.Imm(asm.R0, 0, "normal_target"))
	for _, x := range []struct {
		src, dst int16
		size     asm.Size
	}{{8, 40, asm.DWord}, {32, 96, asm.Word}, {20, 24, asm.Word}, {24, 28, asm.Word}, {28, 32, asm.Word}} {
		add(asm.LoadMem(asm.R1, asm.R0, x.src, x.size), asm.StoreMem(asm.R8, x.dst, asm.R1, x.size))
	}
	add(asm.LoadMem(asm.R0, asm.R6, 8, asm.DWord), asm.JNE.Imm(asm.R0, 3, "restored_target"), asm.Mov.Imm(asm.R1, 3), asm.StoreMem(asm.R8, 88, asm.R1, asm.DWord), asm.StoreImm(asm.R8, 36, 1, asm.Word), asm.Ja.Label("allocate"), asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("normal_target"))
	add(asm.LoadMem(asm.R0, asm.R6, 8, asm.DWord), asm.JEq.Imm(asm.R0, 42, "connect_address"))
	read(asm.R0, asm.R9, l.family, asm.Half)
	add(asm.JEq.Imm(asm.R0, 2, "ipv4_address"), asm.JNE.Imm(asm.R0, 10, "cleanup"))
	// Dual-stack listeners accept IPv4 using AF_INET6 sockets. Admit only mapped
	// IPv4 on BOTH ends, never arbitrary IPv6 addresses with a matching low word.
	for _, offset := range []int32{l.saddr6, l.daddr6} {
		read(asm.R0, asm.R9, offset, asm.DWord)
		add(asm.JNE.Imm(asm.R0, 0, "cleanup"))
		read(asm.R0, asm.R9, offset+8, asm.Word)
		add(asm.LoadImm(asm.R1, 0xffff0000, asm.DWord), asm.JNE.Reg(asm.R0, asm.R1, "cleanup"))
	}
	read(asm.R0, asm.R9, l.daddr6+12, asm.Word)
	add(asm.StoreMem(asm.R8, 28, asm.R0, asm.Word))
	read(asm.R0, asm.R9, l.saddr6+12, asm.Word)
	add(asm.StoreMem(asm.R8, 24, asm.R0, asm.Word), asm.Ja.Label("addresses_done"))
	add(asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("ipv4_address"))
	read(asm.R0, asm.R9, l.daddr, asm.Word)
	add(asm.StoreMem(asm.R8, 28, asm.R0, asm.Word))
	read(asm.R0, asm.R9, l.saddr, asm.Word)
	add(asm.StoreMem(asm.R8, 24, asm.R0, asm.Word))
	// connect has not populated the socket destination yet. Admit only the
	// explicit user sockaddr and the socket's actual target netns; never a global
	// connect hook or an unbounded address copy. FD/inode is checked again at syscall return.
	add(asm.Ja.Label("addresses_done"), asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("connect_address"),
		asm.LoadMem(asm.R0, asm.R6, 32, asm.DWord), asm.JLT.Imm(asm.R0, 16, "cleanup"),
		asm.LoadMem(asm.R3, asm.R6, 24, asm.DWord), asm.Mov.Reg(asm.R1, asm.R8), asm.Add.Imm(asm.R1, payload), asm.Mov.Imm(asm.R2, 16), asm.FnProbeReadUser.Call(), asm.JNE.Imm(asm.R0, 0, "cleanup"),
		asm.LoadMem(asm.R0, asm.R8, payload, asm.Half), asm.JEq.Imm(asm.R0, 2, "connect_v4"), asm.JNE.Imm(asm.R0, 10, "cleanup"),
		asm.LoadMem(asm.R0, asm.R6, 32, asm.DWord), asm.JLT.Imm(asm.R0, 28, "cleanup"), asm.LoadMem(asm.R3, asm.R6, 24, asm.DWord), asm.Mov.Reg(asm.R1, asm.R8), asm.Add.Imm(asm.R1, payload), asm.Mov.Imm(asm.R2, 28), asm.FnProbeReadUser.Call(), asm.JNE.Imm(asm.R0, 0, "cleanup"),
		asm.LoadMem(asm.R0, asm.R8, payload+8, asm.DWord), asm.JNE.Imm(asm.R0, 0, "cleanup"), asm.LoadMem(asm.R0, asm.R8, payload+16, asm.Word), asm.LoadImm(asm.R1, 0xffff0000, asm.DWord), asm.JNE.Reg(asm.R0, asm.R1, "cleanup"),
		asm.LoadMem(asm.R0, asm.R8, payload+20, asm.Word), asm.Ja.Label("connect_destination"),
		asm.LoadMem(asm.R0, asm.R8, payload+4, asm.Word).WithSymbol("connect_v4"),
		asm.StoreMem(asm.R8, 28, asm.R0, asm.Word).WithSymbol("connect_destination"), asm.LoadMem(asm.R0, asm.R8, payload+2, asm.Half), asm.StoreMem(asm.R8, 34, asm.R0, asm.Half))
	add(asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("addresses_done"))
	add(asm.LoadMem(asm.R0, asm.R6, 8, asm.DWord), asm.JEq.Imm(asm.R0, 42, "connect_port_ready"))
	read(asm.R0, asm.R9, l.dport, asm.Half)
	add(asm.StoreMem(asm.R8, 34, asm.R0, asm.Half))
	add(asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("connect_port_ready"))
	add(asm.LoadMem(asm.R0, asm.R8, 8, asm.Word).WithSymbol("restored_target"))
	// 12-byte key: netns LE, peer IPv4 bytes, port BE, direction, zero.
	// A verified outbound listener takes precedence over an accidental collision
	// between the caller's ephemeral source port and a selected application port.
	add(asm.StoreMem(asm.RFP, -80, asm.R0, asm.Word), asm.LoadMem(asm.R0, asm.R8, 28, asm.Word), asm.StoreMem(asm.RFP, -76, asm.R0, asm.Word),
		asm.LoadMem(asm.R0, asm.R8, 32, asm.Half), asm.HostTo(asm.BE, asm.R0, asm.Half), asm.StoreMem(asm.RFP, -72, asm.R0, asm.Half), asm.StoreImm(asm.RFP, -70, 1, asm.Half),
		asm.LoadMapPtr(asm.R1, targets), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -80), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "inbound_lookup"), asm.StoreImm(asm.R8, 96, 1, asm.Word), asm.Ja.Label("target_found"))
	add(asm.LoadMem(asm.R0, asm.R8, 32, asm.Half).WithSymbol("inbound_lookup"), asm.JEq.Imm(asm.R0, 15001, "cleanup"),
		asm.LoadMem(asm.R0, asm.R8, 34, asm.Half), asm.StoreMem(asm.RFP, -72, asm.R0, asm.Half), asm.StoreImm(asm.RFP, -70, 0, asm.Half),
		asm.LoadMapPtr(asm.R1, targets), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -80), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "cleanup"))
	add(asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord).WithSymbol("target_found"), asm.StoreMem(asm.R8, 40, asm.R1, asm.DWord))
	add(asm.LoadMem(asm.R0, asm.R6, 8, asm.DWord), asm.StoreMem(asm.R8, 88, asm.R0, asm.DWord))
	add(asm.JEq.Imm(asm.R0, 3, "allocate"), asm.JEq.Imm(asm.R0, 42, "allocate"), asm.JEq.Imm(asm.R0, 55, "allocate"))
	a = append(a, suppressionLookup(suppressed)...)
	add(asm.JNE.Imm(asm.R0, 0, "cleanup"), asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("allocate"))
	add(asm.StoreImm(asm.RFP, -24, 0, asm.Word), asm.LoadMapPtr(asm.R1, zero), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -24), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "exit"), asm.Mov.Reg(asm.R3, asm.R0), asm.LoadMapPtr(asm.R1, inflight), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8), asm.Mov.Imm(asm.R4, 0), asm.FnMapUpdateElem.Call(), asm.JNE.Imm(asm.R0, 0, "lost"))
	lookup(inflight)
	add(asm.JEq.Imm(asm.R0, 0, "lost"), asm.Mov.Reg(asm.R8, asm.R0))
	for off := int16(0); off < payload; off += 8 {
		add(asm.LoadMem(asm.R1, asm.RFP, -384+off, asm.DWord), asm.StoreMem(asm.R8, off, asm.R1, asm.DWord))
	}
	add(asm.LoadMem(asm.R0, asm.R8, 88, asm.DWord))
	// Capture only the IPv4 original-destination result used by ztunnel itself.
	add(asm.JEq.Imm(asm.R0, 42, "connect_prepare"))
	add(asm.JNE.Imm(asm.R0, 55, "not_metadata"), asm.LoadMem(asm.R0, asm.R8, 96, asm.Word), asm.JEq.Imm(asm.R0, 0, "cleanup"),
		asm.LoadMem(asm.R0, asm.R6, 24, asm.DWord), asm.JNE.Imm(asm.R0, 0, "cleanup"), asm.LoadMem(asm.R0, asm.R6, 32, asm.DWord), asm.JNE.Imm(asm.R0, 80, "cleanup"),
		asm.LoadMem(asm.R0, asm.R6, 40, asm.DWord), asm.StoreMem(asm.R8, 48, asm.R0, asm.DWord), asm.LoadMem(asm.R0, asm.R6, 48, asm.DWord), asm.StoreMem(asm.R8, 56, asm.R0, asm.DWord), asm.StoreImm(asm.R8, 36, 2, asm.Word), asm.Ja.Label("exit"),
		asm.LoadMem(asm.R0, asm.R8, 88, asm.DWord).WithSymbol("not_metadata"))
	add(asm.JNE.Imm(asm.R0, 3, "not_close"), asm.StoreImm(asm.R8, 36, 1, asm.Word), asm.Ja.Label("exit"), asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("not_close"))
	add(asm.LoadMem(asm.R0, asm.R8, 88, asm.DWord))
	for _, id := range []int32{1, 20, 44, 46} {
		add(asm.JEq.Imm(asm.R0, id, "write"))
	}
	add(asm.Ja.Label("args"), asm.StoreImm(asm.R8, 16, 1, asm.Word).WithSymbol("write"))
	add(asm.LoadMem(asm.R0, asm.R6, 24, asm.DWord).WithSymbol("args"), asm.StoreMem(asm.R8, 48, asm.R0, asm.DWord), asm.LoadMem(asm.R0, asm.R6, 32, asm.DWord), asm.StoreMem(asm.R8, 56, asm.R0, asm.DWord), asm.LoadMem(asm.R0, asm.R8, 88, asm.DWord))
	for _, id := range []int32{19, 20} {
		add(asm.JEq.Imm(asm.R0, id, "vector"))
	}
	for _, id := range []int32{46, 47} {
		add(asm.JEq.Imm(asm.R0, id, "msg"))
	}
	// recvfrom/sendto flags at args[3]. Reject PEEK/TRUNC/OOB explicitly for selected socket.
	add(asm.JEq.Imm(asm.R0, 0, "exit"), asm.JEq.Imm(asm.R0, 1, "exit"), asm.LoadMem(asm.R0, asm.R6, 40, asm.DWord), asm.And.Imm(asm.R0, 0x23), asm.JNE.Imm(asm.R0, 0, "damage"), asm.Ja.Label("exit"))
	add(asm.LoadMem(asm.R0, asm.R6, 32, asm.DWord).WithSymbol("msg"), asm.And.Imm(asm.R0, 0x23), asm.JNE.Imm(asm.R0, 0, "damage"), asm.LoadMem(asm.R3, asm.R8, 48, asm.DWord), asm.Add.Imm(asm.R3, 16), asm.Mov.Reg(asm.R1, asm.R8), asm.Add.Imm(asm.R1, 48), asm.Mov.Imm(asm.R2, 16), asm.FnProbeReadUser.Call(), asm.JNE.Imm(asm.R0, 0, "damage"))
	add(asm.StoreImm(asm.R8, 64, 1, asm.Word).WithSymbol("vector"), asm.LoadMem(asm.R0, asm.R8, 56, asm.DWord), asm.JGT.Imm(asm.R0, 8, "damage"), asm.Ja.Label("exit"))
	add(asm.StoreImm(asm.R8, 36, 3, asm.Word).WithSymbol("connect_prepare"), asm.FnKtimeGetNs.Call(), asm.StoreMem(asm.R8, 104, asm.R0, asm.DWord), asm.Ja.Label("exit"))
	add(asm.StoreImm(asm.R8, 36, 4, asm.Word).WithSymbol("damage"), asm.StoreImm(asm.R8, 20, 0, asm.Word), asm.Ja.Label("exit"))
	a = append(a, finish(inflight, loss, a)...)
	enter := a
	a = nil
	// Exit looks up only entries whose full socket and target checks passed at entry.
	add(asm.Mov.Reg(asm.R6, asm.R1), asm.FnGetCurrentPidTgid.Call(), asm.Mov.Reg(asm.R7, asm.R0), asm.RSh.Imm(asm.R0, 32), asm.JNE.Imm(asm.R0, int32(c.PID), "exit"), asm.StoreMem(asm.RFP, -8, asm.R7, asm.DWord))
	lookup(inflight)
	add(asm.JEq.Imm(asm.R0, 0, "exit"), asm.Mov.Reg(asm.R8, asm.R0))
	// In-flight keys contain PID/TID. Recheck the leader birth on exit as well:
	// a recycled TID must not emit a stale record between lifecycle polls.
	add(asm.FnGetCurrentTask.Call(), asm.Mov.Reg(asm.R9, asm.R0))
	read(asm.R9, asm.R9, l.leader, asm.DWord)
	read(asm.R9, asm.R9, l.start, asm.DWord)
	add(asm.Div.Imm(asm.R9, 10000000), asm.LoadImm(asm.R0, int64(c.StartTime), asm.DWord), asm.JNE.Reg(asm.R9, asm.R0, "cleanup"))
	add(asm.LoadMem(asm.R9, asm.R6, 16, asm.DWord), asm.LoadMem(asm.R0, asm.R8, 36, asm.Word), asm.JEq.Imm(asm.R0, 4, "damage"), asm.JEq.Imm(asm.R0, 3, "connect_return"), asm.JEq.Imm(asm.R0, 2, "metadata_return"), asm.JEq.Imm(asm.R0, 0, "data_return"), asm.JNE.Imm(asm.R9, 0, "cleanup"), asm.Ja.Label("emit"), asm.JSLE.Imm(asm.R9, 0, "cleanup").WithSymbol("data_return"))
	a = append(a, suppressionLookup(suppressed)...)
	add(asm.JNE.Imm(asm.R0, 0, "cleanup"), asm.JGT.Imm(asm.R9, 8*1024*1024, "lost_payload"),
		asm.StoreMem(asm.R8, 72, asm.R9, asm.DWord), asm.Mov.Imm(asm.R7, 0), asm.Mov.Imm(asm.R0, 0), asm.StoreMem(asm.R8, 80, asm.R0, asm.DWord),
		asm.LoadMem(asm.R0, asm.R8, 64, asm.DWord), asm.JNE.Imm(asm.R0, 0, "vector_next"),
		asm.LoadMem(asm.R0, asm.R8, 56, asm.DWord), asm.JGT.Reg(asm.R9, asm.R0, "lost"),
		asm.LoadMem(asm.R0, asm.R8, 48, asm.DWord), asm.StoreMem(asm.R8, 120, asm.R0, asm.DWord), asm.StoreMem(asm.R8, 112, asm.R9, asm.DWord), asm.Ja.Label("chunk"))
	add(asm.JEq.Imm(asm.R9, 0, "connect_success").WithSymbol("connect_return"), asm.JNE.Imm(asm.R9, -115, "cleanup"),
		asm.FnGetCurrentTask.Call().WithSymbol("connect_success"), asm.Mov.Reg(asm.R7, asm.R0))
	// Re-resolve the FD at return; never retain a borrowed sock pointer across
	// a syscall where another thread could close/reuse the FD.
	read(asm.R7, asm.R7, l.files, asm.DWord)
	read(asm.R7, asm.R7, l.fdt, asm.DWord)
	read(asm.R0, asm.R7, l.maxfd, asm.Word)
	add(asm.LoadMem(asm.R1, asm.R8, 12, asm.Word), asm.JGE.Reg(asm.R1, asm.R0, "cleanup"))
	read(asm.R7, asm.R7, l.fd, asm.DWord)
	add(asm.LoadMem(asm.R0, asm.R8, 12, asm.Word), asm.LSh.Imm(asm.R0, 3), asm.Add.Reg(asm.R7, asm.R0))
	read(asm.R7, asm.R7, 0, asm.DWord)
	add(asm.StoreMem(asm.RFP, -32, asm.R7, asm.DWord))
	read(asm.R7, asm.R7, l.inode, asm.DWord)
	read(asm.R0, asm.R7, l.ino, asm.DWord)
	add(asm.LoadMem(asm.R1, asm.R8, 0, asm.DWord), asm.JNE.Reg(asm.R0, asm.R1, "cleanup"), asm.LoadMem(asm.R7, asm.RFP, -32, asm.DWord))
	read(asm.R7, asm.R7, l.private, asm.DWord)
	read(asm.R7, asm.R7, l.sk, asm.DWord)
	read(asm.R0, asm.R7, l.family, asm.Half)
	add(asm.JEq.Imm(asm.R0, 2, "connect_source_v4"), asm.JNE.Imm(asm.R0, 10, "cleanup"))
	read(asm.R0, asm.R7, l.saddr6, asm.DWord)
	add(asm.JNE.Imm(asm.R0, 0, "cleanup"))
	read(asm.R0, asm.R7, l.saddr6+8, asm.Word)
	add(asm.LoadImm(asm.R1, 0xffff0000, asm.DWord), asm.JNE.Reg(asm.R0, asm.R1, "cleanup"))
	read(asm.R0, asm.R7, l.saddr6+12, asm.Word)
	add(asm.Ja.Label("connect_source_ready"), asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("connect_source_v4"))
	read(asm.R0, asm.R7, l.saddr, asm.Word)
	add(asm.StoreMem(asm.R8, 24, asm.R0, asm.Word).WithSymbol("connect_source_ready"))
	read(asm.R0, asm.R7, l.sport, asm.Half)
	add(asm.StoreMem(asm.R8, 32, asm.R0, asm.Half), asm.StoreImm(asm.R8, 20, 0, asm.Word), asm.Mov.Imm(asm.R9, 0), asm.Ja.Label("emit"))
	add(asm.JNE.Imm(asm.R9, 0, "cleanup").WithSymbol("metadata_return"),
		asm.LoadMem(asm.R3, asm.R8, 56, asm.DWord), asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -16), asm.Mov.Imm(asm.R2, 4), asm.FnProbeReadUser.Call(), asm.JNE.Imm(asm.R0, 0, "cleanup"), asm.LoadMem(asm.R0, asm.RFP, -16, asm.Word), asm.JLT.Imm(asm.R0, 16, "cleanup"),
		asm.LoadMem(asm.R3, asm.R8, 48, asm.DWord), asm.Mov.Reg(asm.R1, asm.R8), asm.Add.Imm(asm.R1, payload), asm.Mov.Imm(asm.R2, 16), asm.FnProbeReadUser.Call(), asm.JNE.Imm(asm.R0, 0, "cleanup"), asm.LoadMem(asm.R0, asm.R8, payload, asm.Half), asm.JNE.Imm(asm.R0, 2, "cleanup"), asm.StoreImm(asm.R8, 20, 16, asm.Word), asm.Mov.Imm(asm.R9, 16), asm.Ja.Label("emit"))
	// Bounded segmentation preserves every byte through the supported syscall
	// budget. Output truncation belongs to the protocol parser, never this copy.
	add(asm.Add.Imm(asm.R7, 1).WithSymbol("vector_next"), asm.JGT.Imm(asm.R7, 520, "lost_payload"),
		asm.LoadMem(asm.R0, asm.R8, 80, asm.DWord), asm.JGE.Imm(asm.R0, 8, "lost_iovec"),
		asm.LoadMem(asm.R1, asm.R8, 56, asm.DWord), asm.JGE.Reg(asm.R0, asm.R1, "lost_iovec"),
		asm.Mov.Reg(asm.R1, asm.R0), asm.Add.Imm(asm.R1, 1), asm.StoreMem(asm.R8, 80, asm.R1, asm.DWord),
		asm.LSh.Imm(asm.R0, 4), asm.LoadMem(asm.R3, asm.R8, 48, asm.DWord), asm.Add.Reg(asm.R3, asm.R0),
		asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -64), asm.Mov.Imm(asm.R2, 16), asm.FnProbeReadUser.Call(), asm.JNE.Imm(asm.R0, 0, "damage"),
		asm.LoadMem(asm.R0, asm.RFP, -64, asm.DWord), asm.StoreMem(asm.R8, 120, asm.R0, asm.DWord),
		asm.LoadMem(asm.R0, asm.RFP, -56, asm.DWord), asm.LoadMem(asm.R1, asm.R8, 72, asm.DWord),
		asm.JLE.Reg(asm.R0, asm.R1, "iov_size"), asm.Mov.Reg(asm.R0, asm.R1),
		asm.StoreMem(asm.R8, 112, asm.R0, asm.DWord).WithSymbol("iov_size"), asm.JEq.Imm(asm.R0, 0, "vector_next"))
	add(asm.Add.Imm(asm.R7, 1).WithSymbol("chunk"), asm.JGT.Imm(asm.R7, 520, "lost_payload"),
		asm.LoadMem(asm.R9, asm.R8, 112, asm.DWord), asm.JLE.Imm(asm.R9, maxData, "chunk_size"), asm.Mov.Imm(asm.R9, maxData),
		asm.StoreMem(asm.R8, 20, asm.R9, asm.Word).WithSymbol("chunk_size"), asm.JEq.Imm(asm.R9, 0, "lost"),
		asm.Mov.Reg(asm.R1, asm.R8), asm.Add.Imm(asm.R1, payload), asm.Mov.Reg(asm.R2, asm.R9), asm.LoadMem(asm.R3, asm.R8, 120, asm.DWord),
		asm.FnProbeReadUser.Call(), asm.JNE.Imm(asm.R0, 0, "damage"), asm.Ja.Label("emit"))
	add(asm.LoadMem(asm.R0, asm.R8, 36, asm.Word).WithSymbol("emit"), asm.JEq.Imm(asm.R0, 1, "admission_ready"), asm.JNE.Imm(asm.R0, 3, "admission_register"), asm.LoadMem(asm.R0, asm.R8, 32, asm.Half), asm.JEq.Imm(asm.R0, 0, "admission_ready"), asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("admission_register"))
	a = append(a, admissionLookup(suppressed)...)
	add(asm.LoadMem(asm.R0, asm.R8, 36, asm.Word).WithSymbol("admission_ready"), asm.JNE.Imm(asm.R0, 4, "damage_ready"))
	a = append(a, stableSuppressionLookup(suppressed)...)
	add(asm.JEq.Imm(asm.R0, 0, "lost_identity"), asm.StoreImm(asm.R0, 36, 1, asm.Word), asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("damage_ready"))
	add(asm.LoadMem(asm.R0, asm.R8, 36, asm.Word), asm.JEq.Imm(asm.R0, 3, "timestamp_ready"), asm.FnKtimeGetNs.Call(), asm.StoreMem(asm.R8, 104, asm.R0, asm.DWord), asm.Mov.Imm(asm.R0, 0).WithSymbol("timestamp_ready"), asm.LoadMapPtr(asm.R1, ring), asm.Mov.Reg(asm.R2, asm.R8), asm.Mov.Reg(asm.R3, asm.R9), asm.Add.Imm(asm.R3, payload), asm.Mov.Imm(asm.R4, 0), asm.FnRingbufOutput.Call(), asm.JNE.Imm(asm.R0, 0, "lost_ring"),
		asm.LoadMem(asm.R0, asm.R8, 36, asm.Word), asm.JNE.Imm(asm.R0, 0, "cleanup"),
		asm.LoadMem(asm.R0, asm.R8, 72, asm.DWord), asm.Sub.Reg(asm.R0, asm.R9), asm.StoreMem(asm.R8, 72, asm.R0, asm.DWord), asm.JEq.Imm(asm.R0, 0, "cleanup"),
		asm.LoadMem(asm.R0, asm.R8, 120, asm.DWord), asm.Add.Reg(asm.R0, asm.R9), asm.StoreMem(asm.R8, 120, asm.R0, asm.DWord),
		asm.LoadMem(asm.R0, asm.R8, 112, asm.DWord), asm.Sub.Reg(asm.R0, asm.R9), asm.StoreMem(asm.R8, 112, asm.R0, asm.DWord), asm.JNE.Imm(asm.R0, 0, "chunk"), asm.Ja.Label("vector_next"))
	add(asm.StoreImm(asm.R8, 36, 4, asm.Word).WithSymbol("damage"), asm.StoreImm(asm.R8, 20, 0, asm.Word), asm.Mov.Imm(asm.R9, 0), asm.Ja.Label("emit"))
	a = append(a, finish(inflight, loss, a)...)
	return enter, a
}
func finish(inflight, loss int, body asm.Instructions) asm.Instructions {
	used := map[string]bool{}
	for _, ins := range body {
		used[ins.Reference()] = true
	}
	a := asm.Instructions{asm.Mov.Imm(asm.R9, 1).WithSymbol("lost"), asm.Ja.Label("record_loss")}
	for i, name := range []string{"payload", "identity", "admission", "ring", "iovec", "read", "flags", "inode", "generation", "local", "peer", "direction"} {
		if !used["lost_"+name] {
			continue
		}
		a = append(a, asm.LoadImm(asm.R9, int64(uint64(i+1)<<32|1), asm.DWord).WithSymbol("lost_"+name), asm.Ja.Label("record_loss"))
	}
	return append(a,
		asm.StoreImm(asm.RFP, -24, 0, asm.Word).WithSymbol("record_loss"), asm.LoadMapPtr(asm.R1, loss), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -24), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "cleanup"), asm.StoreXAdd(asm.R0, asm.R9, asm.DWord),
		asm.LoadMapPtr(asm.R1, inflight).WithSymbol("cleanup"), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8), asm.FnMapDeleteElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"), asm.Return())
}

// Scratch -128..-89 is disjoint from the target key and iovec scratch. Layout
// matches suppressionKey; every byte is initialized before map lookup.
func stableSuppressionLookup(fd int) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R0, asm.R8, 0, asm.DWord), asm.StoreMem(asm.RFP, -152, asm.R0, asm.DWord),
		asm.LoadMem(asm.R0, asm.R8, 8, asm.Word), asm.StoreMem(asm.RFP, -144, asm.R0, asm.Word), asm.StoreImm(asm.RFP, -140, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, fd), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -152), asm.FnMapLookupElem.Call(),
	}
}
func identityScratch() asm.Instructions {
	var a asm.Instructions
	for _, x := range []struct {
		src, dst int16
		size     asm.Size
	}{{0, -128, asm.DWord}, {40, -120, asm.DWord}, {8, -112, asm.Word}, {24, -108, asm.Word}, {28, -104, asm.Word}, {32, -100, asm.Word}, {96, -96, asm.Word}} {
		a = append(a, asm.LoadMem(asm.R0, asm.R8, x.src, x.size), asm.StoreMem(asm.RFP, x.dst, asm.R0, x.size))
	}
	a = append(a, asm.StoreImm(asm.RFP, -92, 0, asm.Word))
	return a
}
func suppressionLookup(fd int) asm.Instructions {
	a := identityScratch()
	a = append(a, stableSuppressionLookup(fd)...)
	a = append(a, asm.JEq.Imm(asm.R0, 0, "not_suppressed"), asm.LoadMem(asm.R1, asm.R0, 36, asm.Word), asm.JNE.Imm(asm.R1, 1, "not_suppressed"))
	for off := int16(0); off < 32; off += 8 {
		a = append(a, asm.LoadMem(asm.R1, asm.R0, off, asm.DWord), asm.LoadMem(asm.R2, asm.RFP, -128+off, asm.DWord), asm.JNE.Reg(asm.R1, asm.R2, "not_suppressed"))
	}
	a = append(a, asm.LoadMem(asm.R1, asm.R0, 32, asm.Word), asm.LoadMem(asm.R2, asm.RFP, -96, asm.Word), asm.JNE.Reg(asm.R1, asm.R2, "not_suppressed"))
	return append(a, asm.Mov.Imm(asm.R0, 1), asm.Ja.Label("suppression_done"), asm.Mov.Imm(asm.R0, 0).WithSymbol("not_suppressed"), asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("suppression_done"))
}

// NOEXIST preserves a concurrent rejection. An inode collision must never
// restore another tuple: verify the complete admission or stop on ambiguity.
func admissionLookup(fd int) asm.Instructions {
	a := identityScratch()
	a = append(a, stableSuppressionLookup(fd)...)
	a = append(a, asm.JNE.Imm(asm.R0, 0, "admission_verify"),
		asm.LoadMapPtr(asm.R1, fd), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -152), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -128), asm.Mov.Imm(asm.R4, 1), asm.FnMapUpdateElem.Call(), asm.JEq.Imm(asm.R0, 0, "admission_ready"), asm.JNE.Imm(asm.R0, -17, "lost_admission"))
	a = append(a, stableSuppressionLookup(fd)...)
	a = append(a, asm.JEq.Imm(asm.R0, 0, "lost_identity"), asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("admission_verify"))
	for off := int16(0); off < 32; off += 8 {
		a = append(a, asm.LoadMem(asm.R1, asm.R0, off, asm.DWord), asm.LoadMem(asm.R2, asm.RFP, -128+off, asm.DWord), asm.JNE.Reg(asm.R1, asm.R2, "lost_"+[]string{"inode", "generation", "local", "peer"}[off/8]))
	}
	return append(a, asm.LoadMem(asm.R1, asm.R0, 32, asm.Word), asm.LoadMem(asm.R2, asm.RFP, -96, asm.Word), asm.JNE.Reg(asm.R1, asm.R2, "lost_direction"))
}
