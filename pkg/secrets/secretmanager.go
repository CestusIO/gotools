package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"code.cestus.io/libs/gotools/pkg/kestrel"
	"github.com/go-logr/logr"
	vault "github.com/hashicorp/vault/api"
)

type SecretManager struct {
	log           logr.Logger
	kestrelConfig *kestrel.Config
	client        *vault.Client
}

func (sm *SecretManager) ReadJSONSecretRequired(ctx context.Context, path string) (SecretObject, error) {
	secret, err := sm.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("vault read failed: %w", err)
	}
	if secret == nil {
		return nil, fmt.Errorf("secret at %q not found", path)
	}
	b, ok := secret.Data["data"].(map[string]any)
	if !ok {
		return nil, errors.New("not a json")
	}
	return b, nil
}

func ProvideSecretManager(log logr.Logger, kestrelConfig *kestrel.Config, config *Config) (*SecretManager, error) {
	log.Info("ProvideSecretsManager", "environment", kestrelConfig.EnvironmentID, "application", kestrelConfig.ApplicationID)
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = config.Address
	client, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}
	if config.K8S {
		err = loginWithKubernetes(client, *config)
	} else {
		err = useTokenFromEnvOrCLI(client)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to login to vault: %w", err)
	}
	return &SecretManager{
		log:           log,
		kestrelConfig: kestrelConfig,
		client:        client,
	}, nil
}

// For prod/EKS: Use Kubernetes Auth
func loginWithKubernetes(client *vault.Client, config Config) error {
	jwtPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	jwt, err := os.ReadFile(jwtPath)
	if err != nil {
		return fmt.Errorf("unable to read Kubernetes service account token: %w", err)
	}

	role := config.Role // should match the Vault role mapped to your service account
	if role == "" {
		return errors.New("vault role  must be set")
	}

	data := map[string]any{
		"jwt":  string(jwt),
		"role": role,
	}

	resp, err := client.Logical().Write("auth/kubernetes/login", data)
	if err != nil {
		return fmt.Errorf("kubernetes auth login failed: %w", err)
	}

	if resp.Auth == nil || resp.Auth.ClientToken == "" {
		return errors.New("no auth info in Kubernetes login response")
	}

	client.SetToken(resp.Auth.ClientToken)
	return nil
}

// For dev/local: Use VAULT_TOKEN or Vault CLI login
func useTokenFromEnvOrCLI(client *vault.Client) error {
	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		home, _ := os.UserHomeDir()
		tokenPath := fmt.Sprintf("%s/.vault-token", home)
		b, err := os.ReadFile(tokenPath)
		if err != nil {
			return errors.New("VAULT_TOKEN not set and ~/.vault-token not found")
		}
		token = strings.TrimSpace(string(b))
	}

	client.SetToken(token)
	return nil
}
