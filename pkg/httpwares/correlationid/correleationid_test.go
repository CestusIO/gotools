package correlationid_test

import (
	"context"

	"code.cestus.io/libs/gotools/pkg/httpwares/correlationid"
	"code.cestus.io/libs/gotypes/pkg/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CorrelationID", func() {
	It("Fails without a set correlation id ", func() {
		ctx := context.Background()
		_, ok := correlationid.FromContext(ctx)
		Expect(ok).To(BeFalse())
	})
	It("Sets and returns the correct correlation id ", func() {
		var cid types.CorrelationID
		types.Must(&cid, "deadbeef-dead-beef-dead-beef00000075")
		ctx := correlationid.NewContext(context.Background(), cid)
		ccid, ok := correlationid.FromContext(ctx)
		Expect(ok).To(BeTrue())
		Expect(ccid).To(Equal(cid))
	})
})
