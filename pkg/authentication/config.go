package authentication

import (
	"code.cestus.io/libs/flags/pkg/flags"
	"code.cestus.io/libs/gotools/pkg/oidc"
)

type Config struct {
	AdminOIDCConfig  *oidc.Config `json:"admin,omitempty"`
	PlayerOIDCConfig *oidc.Config `json:"player,omitempty"`
	S2SOIDCConfig    *oidc.Config `json:"s2s,omitempty"`
}

type SSMSecret struct {
	Admin  string `json:"admin,omitempty"`
	Player string `json:"player,omitempty"`
	S2S    string `json:"s2s,omitempty"`
}

type OnlineMergedConfig Config

// RegisterConfig registgers a config with a flagset
func RegisterConfig(flagset *flags.FlagSet) *Config {
	conf := Config{
		AdminOIDCConfig:  oidc.RegisterSubConfig(flagset, "admin"),
		PlayerOIDCConfig: oidc.RegisterSubConfig(flagset, "player"),
		S2SOIDCConfig:    oidc.RegisterSubConfig(flagset, "s2s"),
	}
	return &conf
}
