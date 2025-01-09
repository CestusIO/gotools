package metrics

import (
	"net/http"

	"code.cestus.io/libs/buildinfo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Provider is a metrics Provider
type Provider struct {
	serviceName    string
	registry       *prometheus.Registry
	metricsHandler http.Handler
}

// MustRegister registers a prometheus.Collector. It panics on error
func (s Provider) MustRegister(cs ...prometheus.Collector) {
	s.registry.MustRegister(cs...)
}

// ServiceName gets the serviceName of the service metrics are provided for
func (s Provider) ServiceName() string {
	return s.serviceName
}

// MetricsHandler gets the http metrics handler to serve a metrics endpoint
func (s Provider) MetricsHandler() http.Handler {
	return s.metricsHandler
}

// NewProvider creates a metrics Provider
func NewProvider(buildinfo buildinfo.BuildInfo) *Provider {
	registry := prometheus.NewRegistry()
	return &Provider{
		serviceName: buildinfo.Name,
		registry:    registry,
		metricsHandler: promhttp.InstrumentMetricHandler(
			registry, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}),
		),
	}
}
