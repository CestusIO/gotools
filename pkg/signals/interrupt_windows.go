//go:build windows

package signals

import (
	"os"
	"syscall"
)

func SendInterrupt(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Signal(syscall.SIGKILL)
}
