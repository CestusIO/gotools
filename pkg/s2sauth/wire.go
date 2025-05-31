//go:build wireinject
// +build wireinject

// The build tag makes sure the stub is not built in the final build.

package s2sauth

import (
	"github.com/google/wire"
	"code.cestus.io/libs/gotools/pkg/clientware"
)

// S2SAuthProviderSet provides values for s2sAuth
var S2SAuthProviderSet = wire.NewSet(
	ProvideS2STokensource,
	clientware.ProvideS2STripperware,
	ProvideSecretResolver,
)
