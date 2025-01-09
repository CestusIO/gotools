package kestrel

import "code.cestus.io/libs/flags/pkg/flags"

type Config struct {
	ApplicationID       string
	EnvironmentID       string
	RoutingID           string
	ZProjectID          string
	ExternalHostName    string
	HttpClientTimeoutMS uint
}

// RegisterConfig registgers a config with a flagset
func RegisterConfig(flagset *flags.FlagSet) *Config {
	conf := Config{}
	flagset.StringVar(&conf.ApplicationID, 0, "kestrel.applicationid", "", "ID of the application")
	flagset.StringVar(&conf.EnvironmentID, 0, "kestrel.environmentid", "", "ID of the environment")
	flagset.StringVar(&conf.RoutingID, 0, "kestrel.routingid", "951638b3-e767-4d44-b5d9-7e23d190f3dd", "RoutingID global/titel")
	flagset.StringVar(&conf.ZProjectID, 0, "kestrel.zprojectid", "259292329855206149", "Zitadel project id")
	flagset.StringVar(&conf.ExternalHostName, 0, "kestrel.externalhostname", "", "hostname under which services can be reached")
	flagset.UintVar(&conf.HttpClientTimeoutMS, 0, "Kestrel.s2s.client.timeoutms", 5000, "timeout for http calls")
	return &conf
}
