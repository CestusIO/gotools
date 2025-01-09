package authentication

import (
	"code.cestus.io/libs/gotools/pkg/oidc"
	"code.cestus.io/libs/gotools/pkg/secrets"
)

type Secrets struct {
	AdminOIDCSecrets  *oidc.Secrets `json:"admin,omitempty"`
	PlayerOIDCSecrets *oidc.Secrets `json:"player,omitempty"`
	S2SOIDCSecrets    *oidc.Secrets `json:"s2s,omitempty"`
}

// RegisterSecrets registgers a config with a flagset
func RegisterSecrets(flagset *secrets.SecretFlagSet) *Secrets {
	secrets := Secrets{
		AdminOIDCSecrets:  oidc.RegisterSubSecrets(flagset, "authenticationsecret.admin"),
		PlayerOIDCSecrets: oidc.RegisterSubSecrets(flagset, "authenticationsecret.player"),
		S2SOIDCSecrets:    oidc.RegisterSubSecrets(flagset, "authenticationsecret.s2s"),
	}
	return &secrets
}
