package correlationid_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"
)

func TestCorrelationID(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CorrelationID Suite")
}
