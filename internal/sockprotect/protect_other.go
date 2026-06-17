//go:build !unix

package sockprotect

import (
	"fmt"
	"strings"
)

// ProtectFD is unsupported on platforms without Unix-domain fd passing.
func ProtectFD(path string, fd uintptr) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	return fmt.Errorf("fd protection is unsupported on this platform")
}
