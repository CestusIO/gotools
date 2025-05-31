package secrets

import "code.cestus.io/libs/flags/pkg/flags"

type Config struct {
	Enabled bool
	Address string
	Role    string
	K8S     bool
}

// RegisterConfig registgers a config with a flagset
func RegisterConfig(flagset *flags.FlagSet) *Config {
	conf := Config{}
	flagset.BoolVar(&conf.Enabled, 0, "secrets.enabled", "are there secrets to fetch")
	flagset.BoolVar(&conf.K8S, 0, "secrets.k8s", "running in k8s")
	flagset.StringVar(&conf.Address, 0, "secrets.adress", "http://localhost:8200", "vault address")
	flagset.StringVar(&conf.Role, 0, "secrets.role", "", "vault role")
	return &conf
}
