package clientware

import "net/http"

// The RoundTripperFunc type is an adapter to allow the use of ordinary
// functions as RoundTrippers. If f is a function with the appropriate
// signature, RountTripperFunc(f) is a RoundTripper that calls f.
type RoundTripperFunc func(req *http.Request) (*http.Response, error)

// RoundTrip implements the RoundTripper interface.
func (rt RoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return rt(r)
}

type Tripperware func(next http.RoundTripper) http.RoundTripper

// RoundTrippers is a slice of standard roundtrippers
type RoundTrippers []Tripperware

// Chain returns a RoundTrippers type from a slice of Roundtrippers
func Chain(roundtrippers ...Tripperware) RoundTrippers {
	return RoundTrippers(roundtrippers)
}

func (rts RoundTrippers) RoundTripper(next http.RoundTripper) http.RoundTripper {
	return &ChainTripper{next, chain(rts, next), rts}
}

func (rts RoundTrippers) RoundTripperFunc(next RoundTripperFunc) http.RoundTripper {
	return &ChainTripper{next, chain(rts, next), rts}
}

type ChainTripper struct {
	Transport     http.RoundTripper
	chain         http.RoundTripper
	RoundTrippers RoundTrippers
}

func (c *ChainTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return c.chain.RoundTrip(r)
}

func chain(roundtrippers []Tripperware, transport http.RoundTripper) http.RoundTripper {
	if len(roundtrippers) == 0 {
		return transport
	}

	// wrap the transport with the roundtripper chain
	rt := roundtrippers[len(roundtrippers)-1](transport)
	for i := len(roundtrippers) - 2; i >= 0; i-- {
		rt = roundtrippers[i](rt)
	}

	return rt
}

// WrapClient takes an http.Client and wraps its transport in the chain of tripperwares.
func WrapClient(client *http.Client, wares ...Tripperware) *http.Client {
	if len(wares) == 0 {
		return client
	}

	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	for i := len(wares) - 1; i >= 0; i-- {
		transport = wares[i](transport)
	}

	clone := *client
	clone.Transport = transport
	return &clone
}