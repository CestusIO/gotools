//go:build wireinject
// +build wireinject

// The build tag makes sure the stub is not built in the final build.

package tracing

import "github.com/google/wire"

// OtlelProviderSet provides jaeger exporter
var OtlelProviderSet = wire.NewSet(
	ProvideOtlpPipeline,
)
