package rand_test

import (
	"code.cestus.io/libs/gotools/pkg/rand"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Rand", func() {
	It("Uses the charset", func() {
		ss, err := rand.StringFromCharset(10, "A")
		Expect(err).ToNot(HaveOccurred())
		Expect(ss).To(Equal("AAAAAAAAAA"))
	})
	It("Generates the correct size", func() {
		ss, err := rand.StringFromCharset(5, "ABC123")
		Expect(err).ToNot(HaveOccurred())
		Expect(len(ss)).To(Equal(5))
	})
	It("Uses the buildIn charset", func() {
		ss, err := rand.String(5)
		Expect(err).ToNot(HaveOccurred())
		Expect(len(ss)).To(Equal(5))
	})

})
