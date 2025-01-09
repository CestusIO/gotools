package clientware_test

import (
	"net/http"
	"net/http/httptest"
	"time"

	"code.cestus.io/libs/gotools/pkg/clientware"
	"code.cestus.io/libs/gotools/pkg/httputil"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Roundtripper chain", func() {
	When("Using WrapClient", func() {
		It("It calls each Roundtripper once ", func() {
			server := makeTestServer(http.StatusOK, "", 0)
			defer server.Close()
			client := http.Client{
				Transport: httputil.CreateDefaultTransport(),
			}
			tf1Count := 0
			var tf1 clientware.Tripperware = func(next http.RoundTripper) http.RoundTripper {
				return clientware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
					tf1Count++
					return next.RoundTrip(req)
				})
			}
			tf2Count := 0
			var tf2 clientware.Tripperware = func(next http.RoundTripper) http.RoundTripper {
				return clientware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
					tf2Count++
					return next.RoundTrip(req)
				})
			}
			client = *clientware.WrapClient(&client, tf1, tf2)
			_, err := client.Get(server.URL)

			Expect(err).ToNot(HaveOccurred())
			Expect(tf1Count).To(Equal(1))
			Expect(tf2Count).To(Equal(1))
		})
		It("It calls the roundtrippers in order of definition ", func() {
			var order []string
			server := makeTestServer(http.StatusOK, "", 0)
			defer server.Close()
			client := http.Client{
				Transport: httputil.CreateDefaultTransport(),
			}
			tf1Count := 0
			var tf1 clientware.Tripperware = func(next http.RoundTripper) http.RoundTripper {
				return clientware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
					tf1Count++
					order = append(order, "tf1")
					return next.RoundTrip(req)
				})
			}
			tf2Count := 0
			var tf2 clientware.Tripperware = func(next http.RoundTripper) http.RoundTripper {
				return clientware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
					tf2Count++
					order = append(order, "tf2")
					return next.RoundTrip(req)
				})
			}
			client = *clientware.WrapClient(&client, tf1, tf2)
			_, err := client.Get(server.URL)

			Expect(err).ToNot(HaveOccurred())
			Expect(tf1Count).To(Equal(1))
			Expect(tf2Count).To(Equal(1))
			Expect(order).To(Equal([]string{"tf1", "tf2"}))
		})
	})
	When("Using Chain", func() {
		It("It calls each Roundtripper once ", func() {
			server := makeTestServer(http.StatusOK, "", 0)
			defer server.Close()
			client := http.Client{
				Transport: httputil.CreateDefaultTransport(),
			}
			tf1Count := 0
			var tf1 clientware.Tripperware = func(next http.RoundTripper) http.RoundTripper {
				return clientware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
					tf1Count++
					return next.RoundTrip(req)
				})
			}
			tf2Count := 0
			var tf2 clientware.Tripperware = func(next http.RoundTripper) http.RoundTripper {
				return clientware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
					tf2Count++
					return next.RoundTrip(req)
				})
			}
			chain := clientware.Chain(tf1, tf2)
			client.Transport = chain.RoundTripper(client.Transport)
			_, err := client.Get(server.URL)

			Expect(err).ToNot(HaveOccurred())
			Expect(tf1Count).To(Equal(1))
			Expect(tf2Count).To(Equal(1))
		})
		It("It calls the roundtrippers in order of definition ", func() {
			var order []string
			server := makeTestServer(http.StatusOK, "", 0)
			defer server.Close()
			client := http.Client{
				Transport: httputil.CreateDefaultTransport(),
			}
			tf1Count := 0
			var tf1 clientware.Tripperware = func(next http.RoundTripper) http.RoundTripper {
				return clientware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
					tf1Count++
					order = append(order, "tf1")
					return next.RoundTrip(req)
				})
			}
			tf2Count := 0
			var tf2 clientware.Tripperware = func(next http.RoundTripper) http.RoundTripper {
				return clientware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
					tf2Count++
					order = append(order, "tf2")
					return next.RoundTrip(req)
				})
			}
			chain := clientware.Chain(tf1, tf2)
			client.Transport = chain.RoundTripper(client.Transport)
			_, err := client.Get(server.URL)

			Expect(err).ToNot(HaveOccurred())
			Expect(tf1Count).To(Equal(1))
			Expect(tf2Count).To(Equal(1))
			Expect(order).To(Equal([]string{"tf1", "tf2"}))
		})
	})
})

// makeTestServer creates an api server for testing
func makeTestServer(responseCode int, body string, delay int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(responseCode)

		if delay > 0 {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}

		_, err := res.Write([]byte(body))
		if err != nil {
			panic(err)
		}
	}))
}
