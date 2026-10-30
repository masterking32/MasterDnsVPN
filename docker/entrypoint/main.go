package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

func main() {
	launch, err := prepare(environmentSettings(), os.Args[1:], func(c command) error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, c.path, c.args...)
		cmd.Dir = c.dir
		// Successful key generation logs the secret; keep it out of container logs.
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%w\n%s", err, output)
		}
		return nil
	})
	if err == nil {
		err = os.Chdir(launch.dir)
	}
	if err == nil {
		err = replaceProcess(launch.path, append([]string{launch.path}, launch.args...), os.Environ())
	}
	fmt.Fprintln(os.Stderr, "Container startup failed:", err)
	os.Exit(1)
}
