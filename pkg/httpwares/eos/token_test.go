package eos_test

import (
	"context"
	"errors"

	"code.cestus.io/blaze"
	"code.cestus.io/libs/gotools/pkg/httpwares/eos"
	"code.cestus.io/libs/gotools/pkg/httpwares/mocks"
	"code.cestus.io/libs/gotypes/pkg/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("EOSToken", func() {
	var idp types.IDProvider
	var playerID types.PlayerID
	var playerID2 types.PlayerID
	var productID types.EOSProductID
	var sandboxID types.EOSSandboxID
	var deploymentID types.EOSDeploymentID
	BeforeEach(func() {
		idp = types.DefaultIDProvider
		types.Must(&playerID, "374629de-af0b-4668-a655-e2754a52d490")
		types.Must(&playerID2, "394629de-cf0b-4608-a655-e2754a52d600")
		types.Must(&productID, "573c7ad4-819a-4ab4-b110-d90b55533800")
		types.Must(&sandboxID, "793386c1-9c70-4879-b07a-b7b1e5be4a99")
		types.Must(&deploymentID, "710eba5a-a014-4680-8911-8a65f64d39a6")
	})
	Describe("GetToken", func() {
		When("A Header is not set", func() {
			It("Returns a NIL Playerid if the header does not exist", func() {
				mockedSupplier := &mocks.SupplierMock{
					GetFunc: func(key string) string {
						return ""
					},
				}

				token := eos.GetToken(mockedSupplier, idp)
				Expect(token).To(Equal(&eos.EOSTokenContent{}))
			})

		})
		When("A Header is set", func() {
			It("Returns the PlayerID", func() {
				mockedSupplier := &mocks.SupplierMock{
					GetFunc: func(key string) string {
						if key == eos.XEosUser {
							return playerID.String()
						}
						return ""
					},
				}

				token := eos.GetToken(mockedSupplier, idp)
				Expect(token).To(Equal(&eos.EOSTokenContent{
					PlayerID: playerID,
				}))
			})
			It("Returns the ProductID", func() {
				mockedSupplier := &mocks.SupplierMock{
					GetFunc: func(key string) string {
						if key == eos.XEosProductID {
							return productID.String()
						}
						return ""
					},
				}

				token := eos.GetToken(mockedSupplier, idp)
				Expect(token).To(Equal(&eos.EOSTokenContent{
					ProductID: productID,
				}))
			})
			It("Returns the SandboxID", func() {
				mockedSupplier := &mocks.SupplierMock{
					GetFunc: func(key string) string {
						if key == eos.XEosSandboxID {
							return sandboxID.String()
						}
						return ""
					},
				}

				token := eos.GetToken(mockedSupplier, idp)
				Expect(token).To(Equal(&eos.EOSTokenContent{
					SandoxID: sandboxID,
				}))
			})
			It("Returns the DeploymentID", func() {
				mockedSupplier := &mocks.SupplierMock{
					GetFunc: func(key string) string {
						if key == eos.XEosDeploymentID {
							return deploymentID.String()
						}
						return ""
					},
				}

				token := eos.GetToken(mockedSupplier, idp)
				Expect(token).To(Equal(&eos.EOSTokenContent{
					DeploymentID: deploymentID,
				}))
			})
			It("Returns all ID's", func() {
				mockedSupplier := &mocks.SupplierMock{
					GetFunc: func(key string) string {
						switch key {
						case eos.XEosUser:
							return playerID.String()
						case eos.XEosProductID:
							return productID.String()
						case eos.XEosSandboxID:
							return sandboxID.String()
						case eos.XEosDeploymentID:
							return deploymentID.String()
						default:
							return ""
						}
					},
				}

				token := eos.GetToken(mockedSupplier, idp)
				Expect(token).To(Equal(&eos.EOSTokenContent{
					PlayerID:     playerID,
					SandoxID:     sandboxID,
					ProductID:    productID,
					DeploymentID: deploymentID,
				}))
			})
		})
	})
	Describe("Context", func() {
		It("Says not Ok if there is no ticket set", func() {
			ctx := context.Background()
			token, ok := eos.FromContext(ctx)
			Expect(ok).To(BeFalse())
			Expect(token).To(Equal(eos.EOSTokenContent{}))
		})
		It("Returns the ticket if it is set", func() {
			etoken := eos.EOSTokenContent{
				PlayerID:     playerID,
				SandoxID:     sandboxID,
				ProductID:    productID,
				DeploymentID: deploymentID,
			}
			ctx := context.Background()
			nctx := eos.NewContext(ctx, etoken)
			token, ok := eos.FromContext(nctx)
			Expect(ok).To(BeTrue())
			Expect(token).To(Equal(etoken))
		})
	})
	Describe("EOSTokenPlayerIDAuthorizer", func() {
		It("Returns an error when there is no token in the context", func() {
			ctx := context.Background()
			auth := eos.EOSTokenPlayerIDAuthorizer(playerID)
			err := auth(ctx)
			Expect(err).To(HaveOccurred())
			ok := errors.Is(err, &blaze.UnauthenticatedErrorType{})
			Expect(ok).To(BeTrue())
		})
		It("Returns an error when there is an invalid token in the context", func() {
			ctx := context.Background()
			etoken := eos.EOSTokenContent{}
			ctx = eos.NewContext(ctx, etoken)

			auth := eos.EOSTokenPlayerIDAuthorizer(playerID)
			err := auth(ctx)
			Expect(err).To(HaveOccurred())
			ok := errors.Is(err, &blaze.UnauthenticatedErrorType{})
			Expect(ok).To(BeTrue())
		})
		It("Returns an error when the playerID does not match ", func() {
			ctx := context.Background()
			etoken := eos.EOSTokenContent{
				PlayerID:  playerID,
				SandoxID:  sandboxID,
				ProductID: productID,
			}
			ctx = eos.NewContext(ctx, etoken)
			auth := eos.EOSTokenPlayerIDAuthorizer(playerID2)
			err := auth(ctx)
			Expect(err).To(HaveOccurred())
			ok := errors.Is(err, &blaze.PermissionDeniedErrorType{})
			Expect(ok).To(BeTrue())
		})
		It("When the playerID's match ", func() {
			ctx := context.Background()
			etoken := eos.EOSTokenContent{
				PlayerID:  playerID,
				SandoxID:  sandboxID,
				ProductID: productID,
			}
			ctx = eos.NewContext(ctx, etoken)
			auth := eos.EOSTokenPlayerIDAuthorizer(playerID)
			err := auth(ctx)
			Expect(err).ToNot(HaveOccurred())
		})
	})
})
