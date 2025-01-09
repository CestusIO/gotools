package requestid_test

import (
	"context"
	"errors"

	"code.cestus.io/libs/gotools/pkg/httpwares/mocks"
	"code.cestus.io/libs/gotools/pkg/httpwares/requestid"
	idm "code.cestus.io/libs/gotypes/pkg/mocks"
	"code.cestus.io/libs/gotypes/pkg/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CorrelationID", func() {
	It("Fails without a set correlation id ", func() {
		ctx := context.Background()
		_, ok := requestid.FromContext(ctx)
		Expect(ok).To(BeFalse())
	})
	It("Sets and returns the correct correlation id ", func() {
		var rid types.RequestID
		types.Must(&rid, "deadbeef-dead-beef-dead-beef00000075")
		ctx := requestid.NewContext(context.Background(), rid)
		rtid, ok := requestid.FromContext(ctx)
		Expect(ok).To(BeTrue())
		Expect(rtid).To(Equal(rtid))
	})
	It("should return a preexisting requestID", func() {
		sup := mocks.SupplierMock{}
		sup.GetFunc = func(key string) string {
			return "deadbeef-dead-beef-dead-beef00000075"
		}
		rid := requestid.GetRequestID(&sup, types.DefaultIDProvider)
		var erid types.RequestID
		types.Must(&erid, "deadbeef-dead-beef-dead-beef00000075")
		Expect(rid).To(Equal(erid))
	})
	It("should generate a new requestID if the one in the headers was invalid", func() {
		sup := mocks.SupplierMock{}
		var erid types.RequestID
		types.Must(&erid, "deadbeef-dead-beef-dead-beef00000075")
		mockIDP := idm.IDProviderMock{}
		mockIDP.FromStringFunc = func(a types.ID, s string) error {
			return errors.New("error occured")
		}
		mockIDP.NewRandomFunc = func(a types.ID) error {
			erid.As(a)
			return nil
		}
		sup.GetFunc = func(key string) string {
			return "deadbeef-dead-beef-dead-beef000000758"
		}

		rid := requestid.GetRequestID(&sup, &mockIDP)

		Expect(rid).To(Equal(erid))
	})
})
