//go:build linux

package netloom

import (
	"context"
	"syscall"
)

const interfaceBindingSupported = true

// SO_BINDTODEVICE is applied before connect to the actual TCP fd. Never select
// a default device or retry without the option when the kernel rejects it.
func bindNetworkInterface(ctx context.Context, raw syscall.RawConn, device string) error {
	var bindErr error
	err := raw.Control(func(fd uintptr) {
		if bindErr = requestContextError(ctx); bindErr != nil {
			return
		}
		bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
	})
	if err != nil {
		return err
	}
	return bindErr
}
