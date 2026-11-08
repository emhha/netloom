//go:build windows

package netloom

import (
	"errors"
	"syscall"
)

func isPlatformBindingError(err error) bool {
	// Winsock codes differ from Go's synthetic POSIX syscall.Errno constants.
	const (
		wsaAccess  syscall.Errno = 10013 // WSAEACCES
		wsaFamily  syscall.Errno = 10047 // WSAEAFNOSUPPORT
		wsaAddress syscall.Errno = 10049 // WSAEADDRNOTAVAIL
	)
	return errors.Is(err, wsaAccess) || errors.Is(err, wsaFamily) || errors.Is(err, wsaAddress)
}
