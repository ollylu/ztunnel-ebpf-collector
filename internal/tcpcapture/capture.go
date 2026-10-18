package tcpcapture

import (
	"errors"
	"net/netip"
	"time"
)

type Config struct {
	// Suppressions drains rejected connection identities; called serially with consume.
	Suppressions func() []Event
	Continuous   bool
	Refresh      func() (map[Endpoint]uint64, error)
	Check        func() error
	NetNS        uint32
	Ready        func()
	PID          int
	StartTime    uint64
	Server       netip.AddrPort
	Targets      []Endpoint // explicit bounded set; mutually exclusive with Server/NetNS
	Duration     time.Duration
}
type Event struct {
	Damaged  bool // a connection-local byte gap; never parse subsequent bytes until close.
	Outbound bool
	// Connected identifies a connect attempt (0/EINPROGRESS), not TCP handshake success.
	Connected             bool
	TimestampNS           uint64
	OriginalDestination   netip.AddrPort
	Closed                bool
	Generation            uint64
	Inode                 uint64
	NetNS                 uint32
	FD                    uint32
	Write                 bool
	Data                  []byte
	LocalIP, RemoteIP     netip.Addr
	LocalPort, RemotePort uint16
}

var ErrObserverEnded = errors.New("observer generation ended")
