package kestrel

import (
	"context"

	"code.cestus.io/libs/gotypes/pkg/types"
)

func ProvideApplicationID(ctx context.Context, prov types.IDProvider, config *Config) (types.ApplicationID, error) {
	var aID types.ApplicationID
	err := prov.FromString(&aID, config.ApplicationID)
	return aID, err
}
