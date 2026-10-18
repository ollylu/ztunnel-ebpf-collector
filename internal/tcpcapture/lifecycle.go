package tcpcapture

import "errors"

var ErrCleanupFailed = errors.New("capture cleanup failed")

// A retired observer may reload only after all owned resources closed cleanly.
func CanRestartObserver(err error) bool {
	return errors.Is(err, ErrObserverEnded) && !errors.Is(err, ErrCleanupFailed)
}
func CleanupResult(primary, cleanup error) error {
	if cleanup == nil {
		return primary
	}
	return errors.Join(primary, ErrCleanupFailed, cleanup)
}
