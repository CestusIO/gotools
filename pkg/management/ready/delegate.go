package ready

import (
	"sync"

	"github.com/go-logr/logr"
)

//Delegate allows checking if the ready criteria of a service are currently met
type Delegate struct {
	isStrongReady bool
	isWeakReady   bool
	log           logr.Logger
	lock          sync.RWMutex
}

// IsStrongReady returns true when the service is ready only checking strong dependencies
func (d *Delegate) IsStrongReady() bool {
	d.lock.RLock()
	defer d.lock.RUnlock()
	return d.isStrongReady
}

// IsWeakReady returns true when the service is ready only checking weak dependencies
func (d *Delegate) IsWeakReady() bool {
	d.lock.RLock()
	defer d.lock.RUnlock()
	return d.isWeakReady
}

// IsStrongAndWeakReady returns true when the service is ready checking both strong and weak dependencies
func (d *Delegate) IsStrongAndWeakReady() bool {
	d.lock.RLock()
	defer d.lock.RUnlock()
	return d.isStrongReady && d.isWeakReady
}

// UpdateReadyState updates the ready state
func (d *Delegate) UpdateReadyState(strongReady bool, weakReady bool) {
	if d.isStrongReady != strongReady || d.isWeakReady != weakReady {
		d.log.Info("Readyness changed", "strongDependencies", strongReady, "weakDependencies", weakReady)
	}
	d.lock.Lock()
	defer d.lock.Unlock()
	d.isStrongReady = strongReady
	d.isWeakReady = weakReady
}

// ProvideReadyDelegate provides a ready delegate
func ProvideReadyDelegate(log logr.Logger) (*Delegate, error) {
	d := Delegate{
		log: log,
	}
	return &d, nil
}
