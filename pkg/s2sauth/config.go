package s2sauth

import (
	"code.cestus.io/libs/flags/pkg/flags"
)

type Config struct {
	Issuer string
}

// RegisterConfig registgers a config with a flagset
func RegisterConfig(flagset *flags.FlagSet) *Config {
	conf := Config{}
	flagset.StringVar(&conf.Issuer, 0, "s2sauth.issuer", "https://redacted.zitadel.cloud", "token issuer")
	return &conf
}
