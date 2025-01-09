package correlationid

import (
	"context"

	"code.cestus.io/libs/gotypes/pkg/types"
)

const (
	//XCorrelationID is the header value
	XCorrelationID = "X-Correlation-ID"
)

// Supplier is an interface that specifies methods to retrieve and store
// value for a key to an associated carrier.
// Get method retrieves the value for a given key.
// Set method stores the value for a given key.
type Supplier interface {
	Get(key string) string
	Set(key string, value string)
}

type correlationID struct{}

var corelationIDKey = &correlationID{}

// NewContext creates a context with correlation id
func NewContext(ctx context.Context, rid types.CorrelationID) context.Context {
	return context.WithValue(ctx, corelationIDKey, rid)
}

// FromContext returns the CorrelationID from context
func FromContext(ctx context.Context) (types.CorrelationID, bool) {
	cid, ok := ctx.Value(corelationIDKey).(types.CorrelationID)
	return cid, ok
}

// GetCorrelationID returns the X-Correlation-ID from the header
// If there are no X-Request-ID it will generate one
func GetCorrelationID(s Supplier, p types.IDProvider) types.CorrelationID {
	hrid := s.Get(XCorrelationID)
	var correlationID types.CorrelationID
	if hrid == "" {
		err := p.NewRandom(&correlationID)
		if err != nil {
			// this should really never happen since it just reads a number from the random number generator
			// but expecitely set it to NilID
			types.NilID.As(&correlationID)
		}
	}
	return correlationID
}

// SetCorrelationID sets a transaction id using the supplier
func SetCorrelationID(s Supplier, cid string) {
	s.Set(XCorrelationID, cid)
}
