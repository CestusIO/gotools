package iostreams

import (
	"bytes"
	"io"
	"os"

	"github.com/onsi/ginkgo/v2"
)

// IOStreams provides the standard names for iostreams.  This is useful for embedding and for unit testing.
// Inconsistent and different names make it hard to read and review code
type IOStreams struct {
	// In think, os.Stdin
	In io.Reader
	// Out think, os.Stdout
	Out io.Writer
	// ErrOut think, os.Stderr
	ErrOut io.Writer
}

// NewTestIOStreams returns a valid IOStreams and in, out, errout buffers for unit tests
func NewTestIOStreams() (IOStreams, *bytes.Buffer, *bytes.Buffer, *bytes.Buffer) {
	in := &bytes.Buffer{}
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	return IOStreams{
		In:     in,
		Out:    out,
		ErrOut: errOut,
	}, in, out, errOut
}

// NewTestIOStreamsDiscard returns a valid IOStreams that just discards
func NewTestIOStreamsDiscard() IOStreams {
	in := &bytes.Buffer{}
	return IOStreams{
		In:     in,
		Out:    io.Discard,
		ErrOut: io.Discard,
	}
}

// NewGinkoTestIOStreams returns a valid IOStreams for use with ginkgotests
func NewGinkoTestIOStreams() IOStreams {
	in := &bytes.Buffer{}
	return IOStreams{
		In:     in,
		Out:    ginkgo.GinkgoWriter,
		ErrOut: ginkgo.GinkgoWriter,
	}
}

// NewStdIOStreams returns an IOStreams instance using os std streams
func NewStdIOStreams() IOStreams {
	return IOStreams{
		In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr,
	}
}
