package tracing

import (
	"context"
	"fmt"
	"os"
	"strings"

	"code.cestus.io/libs/buildinfo"
	"github.com/go-logr/logr"
	"go.opentelemetry.io/contrib/detectors/aws/ecs"
	"go.opentelemetry.io/contrib/detectors/aws/eks"
	"go.opentelemetry.io/contrib/propagators/aws/xray"
	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

func getEnv(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}
func ProvideOtlpPipeline(ctx context.Context, log logr.Logger, buildinfo buildinfo.BuildInfo, idgen sdktrace.IDGenerator) (trace.TracerProvider, func(), error) {
	agentHostName := getEnv("OTLP_AGENT_HOST", "localhost")
	disabled := getEnv("TRACING_DISABLED", "false")
	port := getEnv("OTLP_AGENT_PORT", "4317")
	if strings.EqualFold(disabled, "true") {
		log.Info("Tracing disabled", "cause", "featureswitch")
		provider := noop.NewTracerProvider()
		otel.SetTracerProvider(provider)
		return provider, func() {}, nil
	}
	exp, err := otlptracegrpc.New(ctx)

	if err != nil {
		log.Info("Tracing disabled", "cause", err.Error())
		provider := noop.NewTracerProvider()
		otel.SetTracerProvider(provider)
		return provider, func() {}, nil
	}
	baseResource := resource.NewSchemaless(
		attribute.String(string(semconv.ServiceNameKey), buildinfo.Name),
		attribute.String("version", buildinfo.Version),
	)
	cloudResource, _ := resource.Detect(ctx, ecs.NewResourceDetector(), eks.NewResourceDetector() /*&gcp.GKE{}*/)
	res, err := resource.Merge(cloudResource, baseResource)
	if err != nil {
		log.Info("Tracing disabled", "cause", err.Error())
		provider := noop.NewTracerProvider()
		otel.SetTracerProvider(provider)
		return provider, func() {}, nil
	}
	tp := sdktrace.NewTracerProvider(
		// Always be sure to batch in production.
		sdktrace.WithBatcher(exp),
		// Record information about this application in an Resource.
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		sdktrace.WithIDGenerator(idgen),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}, b3.New(), xray.Propagator{}))
	log.Info("Tracing enabled", "type", "otlp", "agent", fmt.Sprintf("%s:%s", agentHostName, port))
	return tp, func() { tp.Shutdown(context.Background()) }, err
}

// ProvideJaegerPipeline provides a pipeline - This has been discontinued by otel
// func ProvideJaegerPipeline(ctx context.Context, log logr.Logger, buildinfo buildinfo.BuildInfo, idgen sdktrace.IDGenerator) (trace.TracerProvider, func(), error) {
// 	agentHostName := getEnv("JAEGER_AGENT_HOST", "localhost")
// 	disabled := getEnv("TRACING_DISABLED", "false")
// 	port := getEnv("JAEGER_AGENT_PORT", "6831")

// 	if strings.EqualFold(disabled, "true") {
// 		log.Info("Tracing disabled")
// 		provider := trace.NewNoopTracerProvider()
// 		otel.SetTracerProvider(provider)
// 		return provider, func() {}, nil
// 	}

// 	// Create Jaeger exporter
// 	exp, err := jaeger.NewRawExporter(
// 		//jaeger.WithCollectorEndpoint(jaeger.WithEndpoint("http://localhost:14268/api/traces")),
// 		jaeger.WithAgentEndpoint(jaeger.WithAgentHost(agentHostName), jaeger.WithAgentPort(port)),
// 	)
// 	if err != nil {
// 		log.Info("Tracing disabled", "cause", err.Error())
// 		provider := trace.NewNoopTracerProvider()
// 		otel.SetTracerProvider(provider)
// 		return provider, func() {}, nil
// 	}
// 	baseResource := resource.NewWithAttributes(
// 		semconv.ServiceNameKey.String(buildinfo.Name),
// 		attribute.String("version", buildinfo.Version),
// 	)
// 	cloudResource, _ := resource.Detect(ctx, ecs.NewResourceDetector(), eks.NewResourceDetector(), &gcp.GKE{})
// 	res := resource.Merge(cloudResource, baseResource)
// 	tp := sdktrace.NewTracerProvider(
// 		// Always be sure to batch in production.
// 		sdktrace.WithBatcher(exp),
// 		// Record information about this application in an Resource.
// 		sdktrace.WithResource(res),
// 		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
// 		sdktrace.WithIDGenerator(idgen),
// 	)
// 	otel.SetTracerProvider(tp)
// 	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}, b3.B3{IdGenerator: idgen}, xray.Propagator{}))
// 	log.Info("Tracing enabled", "type", "jaeger", "agent", fmt.Sprintf("%s:%s", agentHostName, port))

// 	return tp, func() { tp.Shutdown(context.Background()) }, err
// }
