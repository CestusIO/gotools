package management

import (
	"net/http"
	"time"

	"code.cestus.io/libs/buildinfo"

	"code.cestus.io/libs/gotools/pkg/management/checks"
)

// Info is a function that retrieves additional information for status.
// the result interface should be json serializable.
type Info func() interface{}

// Handler is an internal interface for the ease of testing (it also serves as a implemntation guarantee)
type Handler interface {

	// RegisterService registers service information for the status endpoint.
	// name is the friendly name of your service
	// version is version information of the service.
	RegisterService(buildinfo buildinfo.BuildInfo)

	// AddStrongCheck adds a check that indicates that this instance of the
	// application is currently healthy.
	// This is used to add a strong dependency check
	AddStrongCheck(check checks.Check, executionPeriod time.Duration, initialDelay time.Duration, initiallyPassing bool)

	// AddWeakCheck adds a check that indicates that this instance of the
	// application is currently healthy.
	// This is used to add a weak dependency check
	AddWeakCheck(check checks.Check, executionPeriod time.Duration, initialDelay time.Duration, initiallyPassing bool)

	// StatusEndpoint is the HTTP handler for the /status endpoint, which is
	// useful if you need to attach it into your own HTTP handler tree.
	StatusEndpoint(http.ResponseWriter, *http.Request)
}
