package main

import "syscall"

func replaceProcess(path string, args, env []string) error {
	// The server becomes PID 1 and handles SIGTERM/SIGINT directly.
	return syscall.Exec(path, args, env)
}
