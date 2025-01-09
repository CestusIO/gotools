package management

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"code.cestus.io/libs/gotools/pkg/kestrel"
	"code.cestus.io/libs/gotools/pkg/management/checks"
)

// Check is a health/readiness check.
type Check func() error

// StatusRouteCheck checks if a get request to the url completes with a 200
func StatusRouteCheck(name string, client *kestrel.HTTPClient, timeout time.Duration, url string) checks.Check {
	if client == nil {
		client = &kestrel.HTTPClient{
			Timeout: timeout,
			// never follow redirects
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	hc := http.Client(*client)
	return &checks.CustomCheck{
		CheckName: name,
		CheckFunc: func() (details interface{}, err error) {
			details = url
			resp, err := hc.Get(url)
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				err = fmt.Errorf("returned status %d", resp.StatusCode)
			}
			return
		},
	}
}

// DNSResolveCheck returns a Check that makes sure the provided host can resolve
// to at least one IP address within the specified timeout.
func DNSResolveCheck(host string, timeout time.Duration) checks.Check {
	resolver := net.Resolver{}
	return &checks.CustomCheck{
		CheckName: host,
		CheckFunc: func() (details interface{}, err error) {
			details = host
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			addrs, err := resolver.LookupHost(ctx, host)
			if err != nil {
				return details, err
			}
			if len(addrs) < 1 {
				return details, fmt.Errorf("could not resolve host")
			}
			return details, nil
		},
	}
}

// HTTPGetCheck returns a Check that performs an HTTP GET request against the
// specified URL. The check fails if the response times out or returns a non-200
// status code.
func HTTPGetCheck(name string, timeout time.Duration, url string) checks.Check {
	return StatusRouteCheck(name, nil, timeout, url)
}
