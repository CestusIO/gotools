package secrets

import (
	"context"
	"encoding/json"
	"fmt"

	"code.cestus.io/libs/gotools/pkg/kestrel"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/go-logr/logr"
)

type SecretManager struct {
	log           logr.Logger
	kestrelConfig *kestrel.Config
	client        secretsmanager.Client
}

type RestructuredSecrets []byte

func ProvideSecretManager(log logr.Logger, kestrelConfig *kestrel.Config, awsConfig aws.Config) *SecretManager {
	log.Info("ProvideSecretsManager", "environment", kestrelConfig.EnvironmentID, "application", kestrelConfig.ApplicationID)
	return &SecretManager{
		log:           log,
		kestrelConfig: kestrelConfig,
		client:        *secretsmanager.NewFromConfig(awsConfig),
	}
}

func parseJSON(input any) any {
	switch v := input.(type) {
	case string:
		var subData map[string]any
		if err := json.Unmarshal([]byte(v), &subData); err == nil {
			return parseJSON(subData)
		}
		return v
	case map[string]any:
		for key, value := range v {
			v[key] = parseJSON(value)
		}
		return v
	case []any:
		for i, value := range v {
			v[i] = parseJSON(value)
		}
		return v
	default:
		return v
	}
}

func ProvideRestructuredSecrets(ctx context.Context, config *Config, ssManager *SecretManager) (RestructuredSecrets, error) {
	// Check if secrets have to be loaded and skip if not
	if !config.Enabled {
		return nil, nil
	}
	environment := ssManager.kestrelConfig.EnvironmentID
	if config.EnvironmentOverride != "" {
		environment = config.EnvironmentOverride
	}
	// get ssm secret for the service
	svi := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(fmt.Sprintf("service/%s%s/%s", config.Version, environment, ssManager.kestrelConfig.ApplicationID)),
	}
	out, err := ssManager.client.GetSecretValue(ctx, svi)
	if err != nil {
		return nil, err
	}
	// Unmarshal into a map
	var data any
	if err := json.Unmarshal([]byte(*out.SecretString), &data); err != nil {
		return nil, err
	}

	// Iterate and attempt to unmarshal embedded JSON strings
	restructured := parseJSON(data)

	// Marshal the result back into JSON
	resultJSON, err := json.MarshalIndent(restructured, "", "  ")
	if err != nil {
		return nil, err
	}

	return (RestructuredSecrets)(resultJSON), nil
}
