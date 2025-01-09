package tracing

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"sync"

	"go.opentelemetry.io/contrib/propagators/aws/xray"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// IDGenerator allows custom generators for TraceID and SpanID.
// type IDGenerator interface {
// 	NewIDs(ctx context.Context) (trace.TraceID, trace.SpanID)
// 	NewSpanID(ctx context.Context, traceID trace.TraceID) trace.SpanID
// }

type randomIDGenerator struct {
	sync.Mutex
	randSource *rand.Rand
}

var _ sdktrace.IDGenerator = &randomIDGenerator{}

// NewSpanID returns a non-zero span ID from a randomly-chosen sequence.
func (gen *randomIDGenerator) NewSpanID(ctx context.Context, traceID trace.TraceID) trace.SpanID {
	gen.Lock()
	defer gen.Unlock()
	sid := trace.SpanID{}
	gen.randSource.Read(sid[:])
	return sid
}

// NewIDs returns a non-zero trace ID and a non-zero span ID from a
// randomly-chosen sequence.
func (gen *randomIDGenerator) NewIDs(ctx context.Context) (trace.TraceID, trace.SpanID) {
	gen.Lock()
	defer gen.Unlock()
	tid := trace.TraceID{}
	gen.randSource.Read(tid[:])
	sid := trace.SpanID{}
	gen.randSource.Read(sid[:])
	return tid, sid
}

// ProvideDefaultIDGenerator provides a random id generator
func ProvideDefaultIDGenerator() sdktrace.IDGenerator {
	gen := &randomIDGenerator{}
	var rngSeed int64
	_ = binary.Read(crand.Reader, binary.LittleEndian, &rngSeed)
	gen.randSource = rand.New(rand.NewSource(rngSeed))
	return gen
}

// ProvideXrayIDGenerator provides an id generator which can be used with aws xray
func ProvideXrayIDGenerator() sdktrace.IDGenerator {
	return xray.NewIDGenerator()
}
