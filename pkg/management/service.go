package management

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"sync"
	"time"

	"errors"

	"code.cestus.io/blaze"
	"code.cestus.io/libs/buildinfo"

	"code.cestus.io/libs/gotools/pkg/httpwares/requestid"
	"code.cestus.io/libs/gotools/pkg/kestrel"
	"code.cestus.io/libs/gotools/pkg/management/checks"
	"code.cestus.io/libs/gotypes/pkg/types"
	"github.com/go-chi/chi/v5"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// StatusOK signifies that the service is healthy and ready to serve requests
	StatusOK = "OK"
	// StatusKO signifies that The service is unhealthy, verify dependencies for troubleshooting
	StatusKO = "KO"

	initialResultMsg = "didn't run yet"

	maxExpectedChecks = 16

	// ReportTypeShort is the value to be passed in the request parameter `type` when a short response is desired.
	ReportTypeShort = "short"
	//FailOnWeakDependency is the request parameter passed if we want to reaturn a 503 when a weak dependency failed.
	FailOnWeakDependency = "failOnWeakDependency"
)

type status struct {
	BuildInfo     *buildinfo.BuildInfo `json:"buildInfo"`
	HostName      string               `json:"hostName"`
	HostIP        string               `json:"hostIP"`
	Status        string               `json:"status"`
	RequestID     types.RequestID      `json:"RequestID"`
	EnvironmentID types.EnvironmentID  `json:"environmentID"`
	ApplicationID types.ApplicationID  `json:"applicationID"`
	Checks        map[string]Result    `json:"checks"`
}

// Service is a management service. It implements the blaze.Service and the Handler interface
type Service struct {
	log           logr.Logger
	mux           *chi.Mux
	mountPath     string
	health        Health
	buildVersion  *buildinfo.BuildInfo
	environmentID types.EnvironmentID
	applicationID types.ApplicationID
	versionGauge  *prometheus.GaugeVec
	hostIP        string
	hostName      string
	ready         ReadyDelegate
	idp           types.IDProvider
}

// Mux implements blaze.Service Mux
func (s *Service) Mux() *chi.Mux {
	return s.mux
}

// MountPath implements blaze.Service MountPath
func (s *Service) MountPath() string {
	return s.mountPath
}

// check implementation guaranties
var _ Handler = (*Service)(nil)
var _ blaze.Service = (*Service)(nil)

// MetricsProvider is an interface defining the expectation for a metrics provider
type MetricsProvider interface {
	MustRegister(cs ...prometheus.Collector)
	ServiceName() string
	MetricsHandler() http.Handler
}

// ReadyDelegate is an interface for ease of testing
type ReadyDelegate interface {
	UpdateReadyState(strongReady bool, weakReady bool)
}

// NewService creates a new management Router
func NewService(log logr.Logger, metrics MetricsProvider, buildinfo buildinfo.BuildInfo, idp types.IDProvider, ready ReadyDelegate, profilingEnabled bool, kestrelConfig *kestrel.Config) *Service {
	versionGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: buildinfo.Name,
		Name:      "build_info",
		Help:      "Runtime build information",
	}, []string{"appName", "version"})

	metrics.MustRegister(versionGauge)

	r := chi.NewRouter()
	h := NewHealth(ready)
	router := Service{
		log:          log,
		mux:          r,
		buildVersion: &buildinfo,
		versionGauge: versionGauge,
		health:       h,
		ready:        ready,
		idp:          idp,
	}
	types.Must(&router.environmentID, kestrelConfig.EnvironmentID)
	types.Must(&router.applicationID, kestrelConfig.ApplicationID)
	if ip, err := externalIP(); err == nil {
		router.hostIP = ip
	}
	if hostname, err := os.Hostname(); err == nil {
		router.hostName = hostname
	}

	router.RegisterService(buildinfo)

	r.Get("/healthz", router.getHealthz)
	r.Get("/liveness", router.getLiveness)
	r.Get("/status", router.getHealthz)
	r.Get("/metrics", metrics.MetricsHandler().ServeHTTP)
	if profilingEnabled {
		r.HandleFunc(
			"/debug/pprof/", pprof.Index,
		)
		r.HandleFunc(
			"/debug/pprof/cmdline", pprof.Cmdline,
		)
		r.HandleFunc(
			"/debug/pprof/profile", pprof.Profile,
		)
		r.HandleFunc(
			"/debug/pprof/symbol", pprof.Symbol,
		)
		r.HandleFunc(
			"/debug/pprof/trace", pprof.Trace,
		)
		r.Handle(
			"/debug/pprof/goroutine", pprof.Handler("goroutine"),
		)
		r.Handle(
			"/debug/pprof/heap", pprof.Handler("heap"),
		)
		r.Handle(
			"/debug/pprof/allocs", pprof.Handler("allocs"),
		)
		r.Handle(
			"/debug/pprof/mutex", pprof.Handler("mutex"),
		)
		r.Handle(
			"/debug/pprof/threadcreate", pprof.Handler("threadcreate"),
		)
		r.Handle(
			"/debug/pprof/block", pprof.Handler("block"),
		)
	}
	return &router
}

// RegisterService implements Handler.RegisterService
func (s *Service) RegisterService(buildinfo buildinfo.BuildInfo) {
	s.buildVersion = &buildinfo
	// set up the metrics label once for all. This will be useful for filtering later all metrics of this instance.
	// see https://www.robustperception.io/exposing-the-software-version-to-prometheus/
	s.versionGauge.WithLabelValues(s.buildVersion.Name, s.buildVersion.Version).Set(1)
}

// AddStrongCheck implements Handler.AddStrongCheck
func (s *Service) AddStrongCheck(check checks.Check, executionPeriod time.Duration, initialDelay time.Duration, initiallyPassing bool) {
	cfg := &Config{
		Check:            check,
		ExecutionPeriod:  executionPeriod,
		InitialDelay:     initialDelay,
		InitiallyPassing: initiallyPassing,
		StrongDependency: true,
	}
	s.health.RegisterCheck(cfg)
}

// AddWeakCheck implements Handler.AddWeakCheck
func (s *Service) AddWeakCheck(check checks.Check, executionPeriod time.Duration, initialDelay time.Duration, initiallyPassing bool) {
	cfg := &Config{
		Check:            check,
		ExecutionPeriod:  executionPeriod,
		InitialDelay:     initialDelay,
		InitiallyPassing: initiallyPassing,
		StrongDependency: false,
	}
	s.health.RegisterCheck(cfg)
}

// StatusEndpoint implements Handler.StatusEndpoint
func (s *Service) StatusEndpoint(w http.ResponseWriter, r *http.Request) {
	s.getHealthz(w, r)
}

func hostName() string {
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return ""
}
func (s *Service) getLiveness(w http.ResponseWriter, r *http.Request) {
	// write out the response code and content type header
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "    ")
	_ = encoder.Encode(s.buildVersion)
}

func (s *Service) getHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	failOnWeakDependency := false
	if r.URL.Query().Get(FailOnWeakDependency) == "true" {
		failOnWeakDependency = true
	}
	results, healthy := s.health.Results(failOnWeakDependency)
	status := &status{
		EnvironmentID: s.environmentID,
		ApplicationID: s.applicationID,
		BuildInfo:     s.buildVersion,
		Status:        StatusOK,
		Checks:        results,
		HostIP:        s.hostIP,
		HostName:      s.hostName,
	}
	w.Header().Set("Content-Type", "application/json")
	if healthy {
		status.Status = StatusOK
		w.WriteHeader(200)
	} else {
		status.Status = StatusKO
		w.WriteHeader(503)
	}
	if rid, ok := requestid.FromContext(r.Context()); ok {
		status.RequestID = rid
	} else {
		status.RequestID = requestid.GetRequestID(r.Header, s.idp)
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "\t")
	var err error
	if r.URL.Query().Get("type") == ReportTypeShort {
		shortResults := make(map[string]string)
		for k, v := range results {
			if v.IsHealthy() {
				shortResults[k] = "PASS"
			} else {
				shortResults[k] = "FAIL"
			}
		}

		err = encoder.Encode(shortResults)
	} else {
		err = encoder.Encode(status)
	}

	if err != nil {
		_, _ = fmt.Fprintf(w, "Failed to render results JSON: %s", err)
	}
}

func externalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("are you connected to the network?")
}

// new

// Health is the API for registering / deregistering health checks, and for fetching the health checks results.
type Health interface {
	// RegisterCheck registers a health check according to the given configuration.
	// Once RegisterCheck() is called, the check is scheduled to run in it's own goroutine.
	// Callers must make sure the checks complete at a reasonable time frame, or the next execution will delay.
	RegisterCheck(cfg *Config) error
	// Deregister removes a health check from this instance, and stops it's next executions.
	// If the check is running while Deregister() is called, the check may complete it's current execution.
	// Once a check is removed, it's results are no longer returned.
	Deregister(name string)
	// Results returns a snapshot of the health checks execution results at the time of calling, and the current health.
	// A system is considered healthy iff all checks are passing
	Results(failOnWeakDependency bool) (results map[string]Result, healthy bool)
	// IsHealthy returns the current health of the system.
	// A system is considered healthy iff all checks are passing.
	IsHealthy() bool
	// DeregisterAll Deregister removes all health checks from this instance, and stops their next executions.
	// It is equivalent of calling Deregister() for each currently registered check.
	DeregisterAll()
	// WithCheckListener allows you to listen to check start/end events
	WithCheckListener(listener CheckListener)
}

// CheckListener can be used to gain check stats or log check transitions.
// Implementations of this interface **must not block!**
// If an implementation blocks, it may result in delayed execution of other health checks down the line.
// It's OK to log in the implementation and it's OK to add metrics, but it's not OK to run anything that
// takes long time to complete such as network IO etc.
type CheckListener interface {
	// OnCheckStarted is called when a check with the specified name has started
	OnCheckStarted(name string)

	// OnCheckCompleted is called when the check with the specified name has completed it's execution.
	// The results are passed as an argument
	OnCheckCompleted(name string, result Result)
}

// Config defines a health Check and it's scheduling timing requirements.
type Config struct {
	// Check is the health Check to be scheduled for execution.
	Check checks.Check
	// ExecutionPeriod is the period between successive executions.
	ExecutionPeriod time.Duration
	// InitialDelay is the time to delay first execution; defaults to zero.
	InitialDelay time.Duration
	// InitiallyPassing indicates when true, the check will be treated as passing before the first run; defaults to false
	InitiallyPassing bool

	// StrongDependency  indicates that the service will not be able to work if this check is not passing
	StrongDependency bool
}

// NewHealth returns a new Health instance.
func NewHealth(ready ReadyDelegate) Health {
	return &health{
		checksListener: noopCheckListener{},
		results:        make(map[string]Result, maxExpectedChecks),
		checkTasks:     make(map[string]checkTask, maxExpectedChecks),
		lock:           sync.RWMutex{},
		ready:          ready,
	}
}

type health struct {
	results        map[string]Result
	checkTasks     map[string]checkTask
	checksListener CheckListener
	lock           sync.RWMutex
	ready          ReadyDelegate
}

func (h *health) RegisterCheck(cfg *Config) error {
	if cfg.Check == nil || cfg.Check.Name() == "" {
		return fmt.Errorf("misconfigured check %v", cfg.Check)
	}

	// checks are initially failing by default, but we allow overrides...
	var initialErr error
	if !cfg.InitiallyPassing {
		initialErr = fmt.Errorf(initialResultMsg)
	}

	h.updateResult(cfg.Check.Name(), initialResultMsg, 0, initialErr, time.Now(), cfg.StrongDependency)
	h.scheduleCheck(h.createCheckTask(cfg), cfg)
	return nil
}

func (h *health) createCheckTask(cfg *Config) *checkTask {
	h.lock.Lock()
	defer h.lock.Unlock()

	task := checkTask{
		stopChan:         make(chan bool, 1),
		check:            cfg.Check,
		strongDependency: cfg.StrongDependency,
	}
	h.checkTasks[cfg.Check.Name()] = task

	return &task
}

type checkTask struct {
	stopChan         chan bool
	ticker           *time.Ticker
	check            checks.Check
	strongDependency bool
}

func (t *checkTask) stop() {
	if t.ticker != nil {
		t.ticker.Stop()
	}
}

func (t *checkTask) execute() (details interface{}, duration time.Duration, err error) {
	startTime := time.Now()
	details, err = t.check.Execute()
	duration = time.Since(startTime)

	return
}

func (h *health) stopCheckTask(name string) {
	h.lock.Lock()
	defer h.lock.Unlock()

	task := h.checkTasks[name]

	task.stop()

	delete(h.results, name)
	delete(h.checkTasks, name)
}

func (h *health) scheduleCheck(task *checkTask, cfg *Config) {
	go func() {
		// initial execution
		if !h.runCheckOrStop(task, time.After(cfg.InitialDelay)) {
			return
		}

		// scheduled recurring execution
		task.ticker = time.NewTicker(cfg.ExecutionPeriod)
		for {
			if !h.runCheckOrStop(task, task.ticker.C) {
				return
			}
		}
	}()
}

func (h *health) runCheckOrStop(task *checkTask, timerChan <-chan time.Time) bool {
	select {
	case <-task.stopChan:
		h.stopCheckTask(task.check.Name())
		return false
	case t := <-timerChan:
		h.checkAndUpdateResult(task, t)
		return true
	}
}

func (h *health) checkAndUpdateResult(task *checkTask, checkTime time.Time) {
	h.checksListener.OnCheckStarted(task.check.Name())
	details, duration, err := task.execute()
	result := h.updateResult(task.check.Name(), details, duration, err, checkTime, task.strongDependency)
	h.checksListener.OnCheckCompleted(task.check.Name(), result)
}

func (h *health) Deregister(name string) {
	h.lock.RLock()
	defer h.lock.RUnlock()

	task, ok := h.checkTasks[name]
	if ok {
		// actual cleanup happens in the task go routine
		task.stopChan <- true
	}
}

func (h *health) DeregisterAll() {
	h.lock.RLock()
	defer h.lock.RUnlock()

	for k := range h.checkTasks {
		h.Deregister(k)
	}
}

func (h *health) Results(failOnWeakDependency bool) (results map[string]Result, healthy bool) {
	h.lock.RLock()
	defer h.lock.RUnlock()

	results = make(map[string]Result, len(h.results))

	healthy = true
	for k, v := range h.results {
		results[k] = v
		if failOnWeakDependency {
			healthy = healthy && v.IsHealthy()
		} else {
			healthy = healthy && (v.IsHealthy() || !v.StrongDependency)
		}
	}

	return
}

func (h *health) IsHealthy() (healthy bool) {
	h.lock.RLock()
	defer h.lock.RUnlock()

	return allHealthy(h.results)
}

func allHealthy(results map[string]Result) (healthy bool) {
	for _, v := range results {
		if !v.IsHealthy() {
			return false
		}
	}

	return true
}

func checkHealthyNess(results map[string]Result) (strongHealthy bool, weakHealthy bool) {
	strongHealthy = true
	weakHealthy = true
	for _, v := range results {
		if !v.IsHealthy() {
			if v.StrongDependency {
				strongHealthy = false
				continue
			}
			weakHealthy = false
		}
	}
	return
}

func (h *health) updateResult(
	name string, details interface{}, checkDuration time.Duration, err error, t time.Time, strongDependency bool) (result Result) {
	t = t.UTC()

	h.lock.Lock()
	defer h.lock.Unlock()

	prevResult, ok := h.results[name]
	result = Result{
		Details:            details,
		Error:              newMarshalableError(err),
		Timestamp:          t.UTC(),
		Duration:           checkDuration,
		TimeOfFirstFailure: nil,
		StrongDependency:   strongDependency,
		Status:             StatusOK,
	}

	if !result.IsHealthy() {
		result.Status = StatusKO
		if ok {
			result.ContiguousFailures = prevResult.ContiguousFailures + 1
			if prevResult.IsHealthy() {
				result.TimeOfFirstFailure = &t
			} else {
				result.TimeOfFirstFailure = prevResult.TimeOfFirstFailure
			}
		} else {
			result.ContiguousFailures = 1
			result.TimeOfFirstFailure = &t
		}
	}

	h.results[name] = result

	strongHealthy, weakHealthy := checkHealthyNess(h.results)
	h.ready.UpdateReadyState(strongHealthy, weakHealthy)

	return result
}

func (h *health) WithCheckListener(listener CheckListener) {
	if listener != nil {
		h.checksListener = listener
	}
}

// Result represents the output of a health check execution.
type Result struct {
	Status string `json:"status"`
	// the details of task Result - may be nil
	Details interface{} `json:"message,omitempty"`
	// the error returned from a failed health check - nil when successful
	Error error `json:"error,omitempty"`
	// the time of the last health check
	Timestamp time.Time `json:"timestamp"`
	// the execution duration of the last check
	Duration time.Duration `json:"durationNS,omitempty"`
	// the number of failures that occurred in a row
	ContiguousFailures int64 `json:"contiguousFailures"`
	// the time of the initial transitional failure
	TimeOfFirstFailure *time.Time `json:"timeOfFirstFailure"`
	// StrongDependency denotes if the result is from a strong dependency
	StrongDependency bool `json:"strongDependency"`
}

// IsHealthy returns true iff the check result snapshot was a success
func (r Result) IsHealthy() bool {
	return r.Error == nil
}

func (r Result) String() string {
	return fmt.Sprintf("Result{details: %s, err: %s, time: %s, contiguousFailures: %d, timeOfFirstFailure:%s}",
		r.Details, r.Error, r.Timestamp, r.ContiguousFailures, r.TimeOfFirstFailure)
}

type marshalableError struct {
	Message string `json:"message,omitempty"`
	Cause   error  `json:"cause,omitempty"`
}

func newMarshalableError(err error) error {
	if err == nil {
		return nil
	}

	mr := &marshalableError{
		Message: err.Error(),
	}

	return mr
}

func (e *marshalableError) Error() string {
	return e.Message
}

type noopCheckListener struct{}

func (noop noopCheckListener) OnCheckStarted(_ string) {}

func (noop noopCheckListener) OnCheckCompleted(_ string, _ Result) {}

// make sure noopCheckListener implements the CheckListener interface
var _ CheckListener = noopCheckListener{}
