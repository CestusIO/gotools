package oidc

import (
	"fmt"

	"code.cestus.io/libs/flags/pkg/flags"
	"code.cestus.io/libs/gotypes/pkg/types"
)

type Config struct {
	URL                    string            `json:"url,omitempty"`
	TenantID               string            `json:"tenant_id,omitempty"`
	Scopes                 types.StringSlice `json:"scopes,omitempty"`
	RequestedIDTokenClaims types.StringSlice `json:"requested_id_token_claims,omitempty"`
	IsOnlineConfig         bool              `json:"storedonline,omitempty"`
}

// RegisterConfig registgers a config with a flagset
func RegisterConfig(flagset *flags.FlagSet) *Config {
	conf := RegisterSubConfig(flagset, "")
	return conf
}

func RegisterSubConfig(flagset *flags.FlagSet, subName string) *Config {
	if len(subName) > 0 {
		subName = fmt.Sprintf("%s.", subName)
	}
	conf := Config{}
	flagset.StringVar(&conf.URL, 0, subName+"oidc.URL", "", "external facing url where this api is reached")
	flagset.StringListVar((*[]string)(&conf.Scopes), 0, subName+"oidc.scopes", "list of scopes")
	flagset.StringListVar((*[]string)(&conf.RequestedIDTokenClaims), 0, subName+"oidc.requestedidtokenclaims", "list of requestedIdTokenClaims")
	flagset.BoolVar(&conf.IsOnlineConfig, 0, subName+"oidc.storedonline", "is this config stored online")
	return &conf
}
