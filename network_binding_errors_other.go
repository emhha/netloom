//go:build !windows

package netloom

func isPlatformBindingError(error) bool { return false }
