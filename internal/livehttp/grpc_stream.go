package livehttp

import (
	"encoding/base64"
	"encoding/binary"
)

type grpcPrefix struct {
	header   []byte
	left     uint32
	current  bodyPrefix
	messages []string
	bytes    int
	count    int
	cut      bool
}

func (g *grpcPrefix) add(p []byte, selected bool, encoding string) error {
	for len(p) > 0 {
		if len(g.header) < 5 {
			n := min(5-len(g.header), len(p))
			g.header = append(g.header, p[:n]...)
			p = p[n:]
			if len(g.header) < 5 {
				return nil
			}
			if g.header[0] > 1 || (g.header[0] == 1 && encoding != "gzip") {
				return errH2
			}
			g.left = binary.BigEndian.Uint32(g.header[1:])
			g.count++
			g.current = bodyPrefix{selected: selected && g.bytes < bodyOutputLimit && g.count <= 32, compressed: g.header[0] == 1}
		}
		n := min(uint64(len(p)), uint64(g.left))
		g.current.add(p[:int(n)])
		p = p[int(n):]
		g.left -= uint32(n)
		if g.left == 0 {
			if g.current.selected {
				b, cut, e := g.current.output()
				if e != nil {
					return e
				}
				keep := min(len(b), bodyOutputLimit-g.bytes)
				g.messages = append(g.messages, base64.StdEncoding.EncodeToString(b[:keep]))
				g.bytes += keep
				g.cut = g.cut || cut || keep < len(b)
			} else if selected {
				g.cut = true
			}
			g.current = bodyPrefix{}
			g.header = nil
		}
	}
	return nil
}
func (g *grpcPrefix) complete() bool { return len(g.header) == 0 && g.left == 0 }
func (g *grpcPrefix) retained() int {
	n := cap(g.current.data) + cap(g.header)
	for _, s := range g.messages {
		n += len(s)
	}
	return n
}
