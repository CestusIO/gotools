//go:build wireinject
// +build wireinject

// The build tag makes sure the stub is not built in the final build.

package awssecrets

import (
	"github.com/google/wire"
)

// SecretsProviderSet provides values for Secrets
var SecretsProviderSet = wire.NewSet(
	ProvideSecretManager,
	ProvideRestructuredSecrets,
)
