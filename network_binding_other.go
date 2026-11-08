//go:build !linux

package netloom

import (
	"context"
	"syscall"
)

const interfaceBindingSupported = false

func bindNetworkInterface(context.Context, syscall.RawConn, string) error {
	return ErrNetworkBindingUnsupported
}
