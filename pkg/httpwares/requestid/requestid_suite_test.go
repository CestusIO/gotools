package requestid_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"
)

func TestRequestID(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "RequestID Suite")
}
