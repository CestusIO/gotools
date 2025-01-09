package kestrel

import (
	"net/http"
	"net/url"
	"time"

	"code.cestus.io/libs/gotools/pkg/clientware"
)

// S2SAPIHTTPClient for s2s authenticated s2s calls
type S2SAPIHTTPClient struct {
	*APIHTTPClient
}

// ProvideS2SAPIHTTPClient returns an Http client that makes s2s calls
func ProvideS2SAPIHTTPClient(client *APIHTTPClient, tw clientware.S2STripperware) (*S2SAPIHTTPClient, error) {
	// Do not use default http client or else all clients will end up piling round trippers on top of each other.
	cl := &HTTPClient{
		Timeout: time.Second * 30,
	}
	apic := &APIHTTPClient{
		HTTPClient: cl,
	}
	if client != nil {
		// Do a copy of the given http client or else all clients will end up piling round trippers on top of each other.
		*apic = *client
	}

	if apic.Transport == nil {
		apic.Transport = http.DefaultTransport
	}
	chain := clientware.Chain(clientware.Tripperware(tw))
	apic.Transport = chain.RoundTripper(apic.Transport)
	return &S2SAPIHTTPClient{
		APIHTTPClient: apic,
	}, nil
}

type ExternalAddress string

func ProvideExternalAddress(config *Config) (ExternalAddress, error) {
	s, err := url.JoinPath(config.ExternalHostName, config.RoutingID, config.EnvironmentID)
	return ExternalAddress(s), err
}
