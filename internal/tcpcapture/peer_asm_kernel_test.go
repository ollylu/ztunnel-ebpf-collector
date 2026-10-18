//go:build linux && amd64 && kernel

package tcpcapture

import (
	"bytes"
	"encoding/binary"
	"github.com/cilium/ebpf/asm"
	"testing"
)

func TestPeerASMEncoding(t *testing.T) {
	l, e := loadLayout()
	if e != nil {
		t.Fatal(e)
	}
	_, xs := programs(Config{}, l, 1, 2, 3, 4, 5, 6)
	for i, x := range xs {
		var b bytes.Buffer
		e = asm.Instructions{x}.Marshal(&b, binary.LittleEndian)
		if e != nil && x.OpCode == asm.InvalidOpCode {
			t.Errorf("bad instruction %d: %+v opcode=%x", i, x, uint16(x.OpCode))
		}
	}
	var b bytes.Buffer
	if e = xs.Marshal(&b, binary.LittleEndian); e != nil {
		for i := 395; i < len(xs) && i < 420; i++ {
			t.Logf("instruction %d: %v opcode=%x", i, xs[i], uint16(xs[i].OpCode))
		}
		t.Fatal(e)
	}
}
