package kestrel

import (
	"context"

	"code.cestus.io/libs/gotypes/pkg/types"
)

func ProvideEnvironmentID(ctx context.Context, prov types.IDProvider, config *Config) (types.EnvironmentID, error) {
	var eID types.EnvironmentID
	err := prov.FromString(&eID, config.EnvironmentID)
	return eID, err
}
