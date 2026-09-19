//go:build !unix

package sockprotect

import "errors"

// ProtectFD is unsupported on platforms without Unix-domain fd passing.
func ProtectFD(path string, fd uintptr) error {
	return errors.New("fd protection is unsupported on this platform")
}
