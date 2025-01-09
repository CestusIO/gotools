package requestid

import (
	"context"

	"code.cestus.io/libs/gotypes/pkg/types"
)

const (
	//XRequestID is the header value
	XRequestID = "X-Request-ID"
)

// Supplier is an interface that specifies methods to retrieve and store
// value for a key to an associated carrier.
// Get method retrieves the value for a given key.
// Set method stores the value for a given key.
type Supplier interface {
	Get(key string) string
	Set(key string, value string)
}

type requestID struct{}

var requestIDKey = &requestID{}

// NewContext creates a context with request id
func NewContext(ctx context.Context, rid types.RequestID) context.Context {
	return context.WithValue(ctx, requestIDKey, rid)
}

// FromContext returns the request id from context
func FromContext(ctx context.Context) (types.RequestID, bool) {
	rid, ok := ctx.Value(requestIDKey).(types.RequestID)
	return rid, ok
}

// GetRequestID returns the X-Request-ID from the header
// If there are no X-Request-ID it will generate one
func GetRequestID(s Supplier, p types.IDProvider) types.RequestID {
	hrid := s.Get(XRequestID)
	var requestID types.RequestID
	if len(hrid) > 0 {
		if err := p.FromString(&requestID, hrid); err != nil {
			// if an error occured let the fallback just generater a valid one. (most likely request id was no id)
			hrid = ""
		}

	}
	if hrid == "" {
		err := p.NewRandom(&requestID)
		if err != nil {
			// this should really never happen since it just reads a number from the random number generator
			// but expecitely set it to NilID
			types.NilID.As(&requestID)
		}
	}
	return requestID
}

// SetRequestID sets a request id using the supplier
func SetRequestID(s Supplier, rid string) {
	s.Set(XRequestID, rid)
}
