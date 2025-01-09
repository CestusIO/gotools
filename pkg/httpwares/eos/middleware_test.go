package eos_test

import (
	"net/http"
	"net/http/httptest"

	"code.cestus.io/libs/gotools/pkg/httpwares/eos"
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
	It("extracts the token into a context", func() {
		req := httptest.NewRequest(http.MethodGet, "http://www.your-domain.com", nil)
		res := httptest.NewRecorder()
		req.Header.Add(eos.XEosUser, playerID.String())
		req.Header.Add(eos.XEosSandboxID, sandboxID.String())
		req.Header.Add(eos.XEosProductID, productID.String())
		req.Header.Add(eos.XEosDeploymentID, deploymentID.String())
		var token eos.EOSTokenContent
		var ok bool
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok = eos.FromContext(r.Context())
		})
		handler := eos.Middleware(idp)(testHandler)
		handler.ServeHTTP(res, req)
		Expect(ok).To(BeTrue())
		Expect(token).To(Equal(eos.EOSTokenContent{
			PlayerID:     playerID,
			SandoxID:     sandboxID,
			ProductID:    productID,
			DeploymentID: deploymentID,
		}))
	})
	It("returns an empty token if the headers are not set", func() {
		req := httptest.NewRequest(http.MethodGet, "http://www.your-domain.com", nil)
		res := httptest.NewRecorder()
		var token eos.EOSTokenContent
		var ok bool
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok = eos.FromContext(r.Context())
		})
		handler := eos.Middleware(idp)(testHandler)
		handler.ServeHTTP(res, req)
		Expect(ok).To(BeTrue())
		Expect(token).To(Equal(eos.EOSTokenContent{}))
	})
})
