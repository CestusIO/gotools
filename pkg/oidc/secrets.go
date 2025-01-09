package oidc

import (
	"fmt"

	"code.cestus.io/libs/gotools/pkg/secrets"
)

type Secrets struct {
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
}

// RegisterSecrets registgers a config with a flagset
func RegisterSecrets(flagset *secrets.SecretFlagSet) *Secrets {
	secrets := RegisterSubSecrets(flagset, "")
	return secrets
}

func RegisterSubSecrets(flagset *secrets.SecretFlagSet, subName string) *Secrets {
	if len(subName) > 0 {
		subName = fmt.Sprintf("%s.", subName)
	}
	secrets := Secrets{}
	flagset.StringVar(&secrets.ClientID, 0, subName+"oidc.clientid", "", "the client ID")
	flagset.StringVar(&secrets.ClientSecret, 0, subName+"oidc.clientsecret", "", "the client secret")
	flagset.StringVar(&secrets.Issuer, 0, subName+"oidc.issuer", "", "e.g. https://login.microsoftonline.com/129ac34a-07de-4800-b1e3-a7941748a97a/v2.0")
	return &secrets
}
