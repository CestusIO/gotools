package s2sauth

import (
	"code.cestus.io/libs/gotools/pkg/secrets"
)

type Secrets struct {
	Type           string `json:"type,omitempty"`
	KeyID          string `json:"keyid,omitempty"`
	Key            string `json:"key,omitempty"`
	ExpirationDate string `json:"expirationDate,omitempty"`
	UserID         string `json:"userId,omitempty"`
}

// RegisterSecrets registgers a config with a flagset
func RegisterSecrets(flagset *secrets.SecretFlagSet) *Secrets {
	secrets := Secrets{}
	flagset.StringVar(&secrets.Type, 0, "s2sauth.type", "", "key internals type")
	flagset.StringVar(&secrets.Key, 0, "s2sauth.key", "", "key internals key")
	flagset.StringVar(&secrets.KeyID, 0, "s2sauth.keyId", "", "key internals keyid")
	flagset.StringVar(&secrets.ExpirationDate, 0, "s2sauth.expirationDate", "", "key internals expirationData")
	flagset.StringVar(&secrets.UserID, 0, "s2sauth.userId", "", "key internals userid")
	return &secrets
}
