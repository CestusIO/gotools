package authorizer

import "code.cestus.io/libs/flags/pkg/flags"

type Config struct {
	Disabled bool
}

// RegisterConfig registgers a config with a flagset
func RegisterConfig(flagset *flags.FlagSet) *Config {
	conf := Config{}
	flagset.BoolVar(&conf.Disabled, 0, "authorizer.disabled", "disables authorization. this is only really usefull for local testing")
	return &conf
}
