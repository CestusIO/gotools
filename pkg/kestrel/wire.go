//go:build wireinject
// +build wireinject

// The build tag makes sure the stub is not built in the final build.

package kestrel

import (
	"github.com/google/wire"
)

// KestrelProviderSet provides values for Kestrel
var KestrelProviderSet = wire.NewSet(
	ProvideApplicationID,
	ProvideEnvironmentID,
	ProvideHTTPClient,
	ProvideAPIHTTPClient,
	ProvideS2SAPIHTTPClient,
	ProvideExternalAddress,
)
