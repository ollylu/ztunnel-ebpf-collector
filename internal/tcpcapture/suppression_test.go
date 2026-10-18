package tcpcapture

import (
	"errors"
	"net/netip"
	"testing"
)

func suppressionEvent() Event {
	return Event{Inode: 10, Generation: 1, NetNS: 2, LocalIP: netip.MustParseAddr("10.0.0.1"), RemoteIP: netip.MustParseAddr("10.0.0.2"), LocalPort: 40000, RemotePort: 8080}
}
func TestSuppressionIdentityIsolation(t *testing.T) {
	e := suppressionEvent()
	seen := map[[40]byte]bool{}
	variants := []Event{e, e, e, e, e, e, e, e, e}
	variants[1].Inode++
	variants[2].Generation++
	variants[3].NetNS++
	variants[4].LocalIP = netip.MustParseAddr("10.0.0.3")
	variants[5].RemoteIP = netip.MustParseAddr("10.0.0.3")
	variants[6].LocalPort++
	variants[7].RemotePort++
	variants[8].Outbound = true
	for _, v := range variants {
		k, err := suppressionKey(v)
		if err != nil || seen[k] {
			t.Fatal("identity collision", v, err)
		}
		seen[k] = true
	}
	e.Generation = 0
	if _, err := suppressionKey(e); err == nil {
		t.Fatal("zero generation accepted")
	}
	e = suppressionEvent()
	e.LocalIP = netip.MustParseAddr("::1")
	if _, err := suppressionKey(e); err == nil {
		t.Fatal("non-IPv4 admitted")
	}
}
func TestSuppressionLifecycleAndCapacity(t *testing.T) {
	// The backing map double models only kernel storage; observable owner state,
	// limits and failures are exercised through the production controller.
	backing := map[[40]byte]bool{}
	s := suppressionSet{put: func(k [40]byte) error { backing[k] = true; return nil }, remove: func(k [40]byte) error { delete(backing, k); return nil }}
	e := suppressionEvent()
	active := map[Endpoint]uint64{e.Target(): 1}
	for i := uint64(1); i <= 64; i++ {
		e.Inode = i
		if err := s.add([]Event{e}, active); err != nil {
			t.Fatal(err)
		}
	}
	if len(backing) != 64 {
		t.Fatal("filters not installed", len(backing))
	}
	e.Inode = 65
	if err := s.add([]Event{e}, active); err == nil {
		t.Fatal("capacity not enforced")
	}
	e.Inode = 1
	if err := s.close(e); err != nil {
		t.Fatal(err)
	}
	e.Inode = 65
	if err := s.add([]Event{e}, active); err != nil {
		t.Fatal("close did not reclaim capacity", err)
	}
	active[e.Target()] = 2
	if err := s.reconcile(active); err != nil || len(backing) != 0 || len(s.entries) != 0 {
		t.Fatal("revoked identities remain", err)
	}
	if err := s.add([]Event{e}, active); err != nil || len(backing) != 0 {
		t.Fatal("stale feedback reinstalled", err)
	}
	e.Generation = 2
	if err := s.add([]Event{e}, active); err != nil || len(backing) != 1 {
		t.Fatal("new generation blocked", err)
	}
	boom := errors.New("map failed")
	s.remove = func([40]byte) error { return boom }
	if err := s.close(e); !errors.Is(err, boom) || len(s.entries) != 1 {
		t.Fatal("delete failure hidden", err)
	}
	s.put = func([40]byte) error { return boom }
	e.Inode++
	if err := s.add([]Event{e}, active); !errors.Is(err, boom) || len(s.entries) != 1 {
		t.Fatal("update failure hidden", err)
	}
}

// TCP teardown may clear a local tuple (including an unconnected socket that
// matched the target). Close must not turn this into a global protection error.
func TestSuppressionCloseWithClearedTuple(t *testing.T) {
	backing := map[[40]byte]bool{}
	s := suppressionSet{put: func(k [40]byte) error { backing[k] = true; return nil }, remove: func(k [40]byte) error { delete(backing, k); return nil }}
	e := suppressionEvent()
	if err := s.add([]Event{e}, map[Endpoint]uint64{e.Target(): 1}); err != nil {
		t.Fatal(err)
	}
	closed := e
	closed.LocalPort = 0
	closed.LocalIP = netip.Addr{}
	other := closed
	other.Inode++
	if err := s.close(other); err != nil || len(backing) != 1 {
		t.Fatal("untracked close must be harmless", err)
	}
	other = closed
	other.Generation++
	if err := s.close(other); err != nil || len(backing) != 1 {
		t.Fatal("different generation removed", err)
	}
	if err := s.close(closed); err != nil || len(backing) != 0 {
		t.Fatal("same socket not released", err)
	}
}

func TestParsedAdmissionsShareBudgetAndRelease(t *testing.T) {
	s := suppressionSet{put: func([40]byte) error { return nil }, remove: func([40]byte) error { return nil }}
	e := suppressionEvent()
	active := map[Endpoint]uint64{e.Target(): 1}
	for i := 1; i <= 130; i++ {
		e.Inode = uint64(i)
		if err := s.track(e, active); err != nil {
			t.Fatal(err)
		}
		if err := s.add([]Event{e}, active); err != nil {
			t.Fatal(err)
		}
		if len(s.entries) != 1 {
			t.Fatal("double counted", len(s.entries))
		}
		c := e
		c.LocalPort = 0
		if err := s.close(c); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.entries) != 0 || len(s.filtered) != 0 {
		t.Fatal("closed identities retained")
	}
	for i := 1; i <= 64; i++ {
		e.Inode = uint64(i)
		if err := s.track(e, active); err != nil {
			t.Fatal(err)
		}
	}
	e.Inode = 65
	if err := s.track(e, active); err == nil {
		t.Fatal("parsed admission bypassed shared budget")
	}
	if err := s.reconcile(map[Endpoint]uint64{}); err != nil || len(s.entries) != 0 {
		t.Fatal("revocation", err)
	}
}
