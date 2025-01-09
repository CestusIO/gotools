package clientware

import (
	"net/http"

	"code.cestus.io/libs/gotools/pkg/httputil"
	"code.cestus.io/libs/gotools/pkg/httpwares/requestid"
	"code.cestus.io/libs/gotypes/pkg/types"
)

// RequestID wraps the transport and adds the request id to the request for forwarding
func RequestID(next http.RoundTripper, p types.IDProvider) http.RoundTripper {
	return RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		r := httputil.CloneRequest(req)
		id, ok := requestid.FromContext(r.Context())
		if ok {
			requestid.SetRequestID(r.Header, id.String())
		} else {
			var rid types.RequestID
			err := p.NewRandom(&rid)
			if err != nil {
				// this should really never happen since it just reads a number from the random number generator
				// but expecitely set it to NilID
				types.NilID.As(&rid)
				return nil, err
			}
			ctx := requestid.NewContext(r.Context(), rid)
			requestid.SetRequestID(r.Header, rid.String())
			r = r.WithContext(ctx)
		}
		return next.RoundTrip(r)
	})
}
