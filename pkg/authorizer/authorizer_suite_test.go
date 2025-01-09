package authorizer_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"
)

func TestTransactionID(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Authorizer Suite")
}
