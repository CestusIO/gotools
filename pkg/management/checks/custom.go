package checks

// CustomCheck is a simple Check implementation if all needed is a functional check
type CustomCheck struct {
	// CheckName s the name of the check.
	CheckName string
	// CheckFunc is a function that runs a single time check, and returns an error when the check fails, and an optional details object.
	CheckFunc func() (details interface{}, err error)
}

// does implement Check
var _ Check = (*CustomCheck)(nil)

// Name is the name of the check.
// Check names must be metric compatible.
func (check *CustomCheck) Name() string {
	return check.CheckName
}

// Execute runs the given Checkfunc, and return it's output.
func (check *CustomCheck) Execute() (details interface{}, err error) {
	if check.CheckFunc == nil {
		return "Unimplemented check", nil
	}

	return check.CheckFunc()
}

// NewCustomCheck creates a custom check
func NewCustomCheck(name string, f CheckFunc) Check {
	return &CustomCheck{
		CheckName: name,
		CheckFunc: f,
	}
}
