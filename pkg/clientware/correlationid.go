package clientware

import (
	"net/http"

	"code.cestus.io/libs/gotools/pkg/httputil"
	"code.cestus.io/libs/gotools/pkg/httpwares/correlationid"
	"code.cestus.io/libs/gotypes/pkg/types"
)

func CorrelationID(p types.IDProvider) Tripperware {
	return func(next http.RoundTripper) http.RoundTripper {
		return RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			r := httputil.CloneRequest(req)
			id, ok := correlationid.FromContext(r.Context())
			if ok {
				correlationid.SetCorrelationID(r.Header, id.String())
			} else {
				var cid types.CorrelationID
				err := p.NewRandom(&cid)
				if err != nil {
					// this should really never happen since it just reads a number from the random number generator
					// but expecitely set it to NilID
					types.NilID.As(&cid)
					return nil, err
				}
				ctx := correlationid.NewContext(r.Context(), cid)
				correlationid.SetCorrelationID(r.Header, cid.String())
				r = r.WithContext(ctx)
			}
			return next.RoundTrip(r)
		})
	}
}
