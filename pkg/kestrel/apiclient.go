package kestrel

import (
	"net/http"
	"time"

	"github.com/go-logr/logr"
)

// HTTPClient is a http client
type HTTPClient http.Client

func (c *S2SAPIHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.Transport.RoundTrip(req)
}

// ProvideHTTPClient provides a http client
func ProvideHTTPClient(log logr.Logger, config *Config) *HTTPClient {
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}

	ac := &HTTPClient{Transport: tr, Timeout: (time.Millisecond * time.Duration(config.HttpClientTimeoutMS))}
	return ac
}

type APIHTTPClient struct {
	*HTTPClient
}

// ProvideAPIHTTPClient provides a http client
func ProvideAPIHTTPClient(log logr.Logger, config *Config, client *HTTPClient) *APIHTTPClient {
	ac := &APIHTTPClient{
		HTTPClient: client,
	}
	return ac
}
