package tcpcapture

import (
	"errors"
	"testing"
)

func TestCleanupFailurePreventsObserverRestart(t *testing.T) {
	failure := errors.New("close failed")
	if !CanRestartObserver(ErrObserverEnded) {
		t.Fatal("clean observer exit must restart")
	}
	if CanRestartObserver(CleanupResult(ErrObserverEnded, failure)) {
		t.Fatal("failed cleanup must not reload")
	}
	if !errors.Is(CleanupResult(nil, failure), failure) {
		t.Fatal("close cause lost")
	}
	if CanRestartObserver(errors.New("IO error")) {
		t.Fatal("unknown error must not restart")
	}
	if CleanupResult(nil, nil) != nil {
		t.Fatal("successful cleanup introduced error")
	}
}
