package authorizer_test

import (
	"context"
	"errors"

	"code.cestus.io/blaze"
	"code.cestus.io/libs/gotools/pkg/authorizer"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Authorizer", func() {

	It("should call each authorizer function exactly once", func() {
		af1cnt := 0
		af1 := func(ctx context.Context) error {
			af1cnt++
			return nil
		}
		af2cnt := 0
		af2 := func(ctx context.Context) error {
			af2cnt++
			return nil
		}
		config := authorizer.Config{}
		ctx := context.Background()
		err := authorizer.AuthorizeWith(ctx, config, af1, af2)
		Expect(err).ToNot(HaveOccurred())
		Expect(af1cnt).To(Equal(1))
		Expect(af2cnt).To(Equal(1))
	})
	It("should return nil when all authorizer functions pass", func() {
		af1cnt := 0
		af1 := func(ctx context.Context) error {
			af1cnt++
			return nil
		}
		af2cnt := 0
		af2 := func(ctx context.Context) error {
			af2cnt++
			return nil
		}
		config := authorizer.Config{}
		ctx := context.Background()
		err := authorizer.AuthorizeWith(ctx, config, af1, af2)
		Expect(err).ToNot(HaveOccurred())
		Expect(af1cnt).To(Equal(1))
		Expect(af2cnt).To(Equal(1))
	})
	It("should return a permissionDenied error if one of the authorizer functions returns an error", func() {
		af1cnt := 0
		af1 := func(ctx context.Context) error {
			af1cnt++
			return nil
		}
		af2cnt := 0
		af2 := func(ctx context.Context) error {
			af2cnt++
			return errors.New("problem")
		}
		config := authorizer.Config{}
		ctx := context.Background()
		err := authorizer.AuthorizeWith(ctx, config, af1, af2)
		Expect(err).To(MatchError(blaze.ErrorPermissionDenied("")))
		Expect(af1cnt).To(Equal(1))
		Expect(af2cnt).To(Equal(1))
	})
	It("should not return an  error when it is disabled in the config", func() {
		af1cnt := 0
		af1 := func(ctx context.Context) error {
			af1cnt++
			return nil
		}
		af2cnt := 0
		af2 := func(ctx context.Context) error {
			af2cnt++
			return errors.New("problem")
		}
		config := authorizer.Config{
			Disabled: true,
		}
		ctx := context.Background()
		err := authorizer.AuthorizeWith(ctx, config, af1, af2)
		Expect(err).ToNot(HaveOccurred())
		Expect(af1cnt).To(Equal(0))
		Expect(af2cnt).To(Equal(0))
	})
})
