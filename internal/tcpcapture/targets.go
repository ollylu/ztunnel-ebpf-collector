package tcpcapture

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const MaxTargets = 32

// Endpoint identifies the business-side socket, independent of protocol.
type Endpoint struct {
	Outbound bool // Server holds peer Pod IP and the verified local ztunnel listener port.
	NetNS    uint32
	Server   netip.AddrPort
}

func (e Endpoint) Key() (key [12]byte) {
	binary.LittleEndian.PutUint32(key[:4], e.NetNS)
	ip := e.Server.Addr().As4()
	copy(key[4:8], ip[:])
	binary.BigEndian.PutUint16(key[8:10], e.Server.Port())
	if e.Outbound {
		key[10] = 1
	}
	return key
}

func (c Config) Endpoints() ([]Endpoint, error) {
	targets := c.Targets
	if len(targets) == 0 && c.Continuous && c.Refresh != nil && c.NetNS == 0 && !c.Server.IsValid() {
		return nil, nil
	}
	if len(targets) == 0 {
		targets = []Endpoint{{NetNS: c.NetNS, Server: c.Server}}
	} else if c.NetNS != 0 || c.Server.IsValid() {
		return nil, errors.New("ambiguous single and multiple targets")
	}
	if len(targets) > MaxTargets {
		return nil, errors.New("target budget exhausted (maximum 32)")
	}
	seen := make(map[Endpoint]bool, len(targets))
	for _, e := range targets {
		if e.NetNS == 0 || !e.Server.Addr().Is4() || e.Server.Port() == 0 || seen[e] {
			return nil, errors.New("invalid or duplicate target endpoint")
		}
		seen[e] = true
	}
	return append([]Endpoint(nil), targets...), nil
}

// Target uses the same selector as the kernel, distinct from the socket peer tuple.
func (e Event) Target() Endpoint {
	port := e.RemotePort
	if e.Outbound {
		port = e.LocalPort
	}
	return Endpoint{NetNS: e.NetNS, Server: netip.AddrPortFrom(e.RemoteIP, port), Outbound: e.Outbound}
}
