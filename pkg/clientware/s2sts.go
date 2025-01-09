package clientware

import (
	"errors"
	"net/http"

	"code.cestus.io/libs/gotools/pkg/httputil"
	"golang.org/x/oauth2"
)

type S2STokensource oauth2.TokenSource

type S2STripperware Tripperware

func ProvideS2STripperware(ts S2STokensource) S2STripperware {
	ts = oauth2.ReuseTokenSource(nil, ts) // we can always wrap a tokensource
	return func(next http.RoundTripper) http.RoundTripper {
		return RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			reqBodyClosed := false
			if req.Body != nil {
				defer func() {
					if !reqBodyClosed {
						req.Body.Close()
					}
				}()
			}

			if ts == nil {
				return nil, errors.New("tokensource is nil")
			}
			token, err := ts.Token()
			if err != nil {
				return nil, err
			}

			r := httputil.CloneRequest(req) // per RoundTripper contract
			token.SetAuthHeader(r)

			// req.Body is assumed to be closed by the base RoundTripper.
			reqBodyClosed = true
			return next.RoundTrip(r)
		})
	}
}
