//go:build wireinject
// +build wireinject

// The build tag makes sure the stub is not built in the final build.

package authentication

import (
	"github.com/google/wire"
)

// AuthenticationProviderSet provides values for Kestrel
var AuthenticationProviderSet = wire.NewSet(
	ProvideAdminClientApp,
	ProvideAdminMiddlewareBuilder,
	ProvidePlayerClientApp,
	ProvidePlayerMiddlewareBuilder,
	ProvideS2SClientApp,
	ProvideS2SMiddlewareBuilder,
	ProvideAuthMiddlewares,
)
