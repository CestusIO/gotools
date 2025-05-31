package s2sauth

import (
	"context"

	"code.cestus.io/libs/gotools/pkg/secrets"
)

type Resolver struct {
	config        *Config
	secretManager *secrets.SecretManager
}

var _ secrets.Resolver = (*Resolver)(nil)

func ProvideSecretResolver(config *Config, sm *secrets.SecretManager) *Resolver {
	r := Resolver{
		config:        config,
		secretManager: sm,
	}
	return &r
}

func (r Resolver) Resolve(ctx context.Context, sobject secrets.SecretObject) (secrets.SecretObject, error) {
	secret, err := r.secretManager.ReadJSONSecretRequired(ctx, r.config.Path)
	if err != nil {
		return sobject, err
	}
	sobject["s2sauth"] = secret
	return sobject, nil
}
