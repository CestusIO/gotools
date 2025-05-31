package awssecrets

import "code.cestus.io/libs/flags/pkg/flags"

type Config struct {
	Enabled             bool
	EnvironmentOverride string
	Version             string
}

// RegisterConfig registgers a config with a flagset
func RegisterConfig(flagset *flags.FlagSet) *Config {
	conf := Config{}
	flagset.BoolVar(&conf.Enabled, 0, "secrets.enabled", "are there secrets to fetch")
	flagset.StringVar(&conf.EnvironmentOverride, 0, "secrets.environmentoverride", "", "possible to override the kestrel environment")
	flagset.StringVar(&conf.Version, 0, "secrets.version", "v1/", "pathprefix in secretsmanager e.g. v1/")
	return &conf
}
