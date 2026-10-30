//go:build !linux

package main

import "fmt"

func replaceProcess(path string, args, env []string) error {
	return fmt.Errorf("the container entrypoint requires Linux")
}
