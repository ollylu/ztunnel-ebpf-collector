//go:build !linux || !amd64

package tcpcapture

import (
	"context"
	"errors"
)

func Run(context.Context, Config, func(Event) error) error {
	return errors.New("capture requires Linux amd64")
}
