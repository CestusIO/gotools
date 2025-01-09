package signals

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/go-logr/logr"
)

// NewInterruptNotifier returns a channel wich is closed on a received interrupt
func NewInterruptNotifier(log logr.Logger) chan struct{} {
	f := make(chan struct{})
	go func(notif chan struct{}) {
		quit := make(chan os.Signal, 1)

		signal.Notify(quit, os.Interrupt)
		signal.Notify(quit, syscall.SIGTERM)
		sig := <-quit
		log.V(1).Info("Shutting down", "reason", sig.String())
		close(notif)
	}(f)
	return f
}
