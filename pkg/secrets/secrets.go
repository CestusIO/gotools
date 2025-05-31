package secrets

import (
	"context"
	"encoding/json"
	"fmt"

	"code.cestus.io/libs/flags/pkg/flags"
)

type SecretFlagSet struct{ flags.FlagSet }

func (s *SecretFlagSet) AsFlagSet() *flags.FlagSet {
	return &s.FlagSet
}

type Resolver interface {
	Resolve(ctx context.Context, sobject SecretObject) (SecretObject, error)
}

type Resolvers []Resolver

type SecretObject map[string]any

func MergeSecretObjectsStrict(obj ...SecretObject) (SecretObject, error) {
	result := make(map[string]any)
	for _, m := range obj {
		for k, v := range m {
			if _, exists := result[k]; exists {
				return nil, fmt.Errorf("merge conflict: key %q exists in multiple objects", k)
			}
			result[k] = v
		}
	}
	return result, nil
}

type RestructuredSecrets []byte

func ProvideRestructuredSecrets(ctx context.Context, secretConfig *Config, resolvers Resolvers) (RestructuredSecrets, error) {
	// Check if secrets have to be loaded and skip if not
	if !secretConfig.Enabled {
		return nil, nil
	}
	document := make(SecretObject)

	for _, resolver := range resolvers {
		var err error
		document, err = resolver.Resolve(ctx, document)
		if err != nil {
			return nil, err
		}
	}

	doc, err := json.MarshalIndent(document, "", " ")
	return doc, err
}
