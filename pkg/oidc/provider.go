package oidc

import (
	"context"
	"fmt"
	"net/http"

	"code.cestus.io/libs/log"
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"golang.org/x/oauth2"
)

// Provider is a wrapper around go-oidc provider to also provide the following features:
// 1. lazy initialization/querying of the provider
// 2. automatic detection of change in signing keys
// 3. convenience function for verifying tokens
type Provider interface {
	Endpoint() (*oauth2.Endpoint, error)

	ParseConfig() (*OIDCConfiguration, error)

	Verify(ctx context.Context, clientID, tokenString string) (*gooidc.IDToken, error)
}

type providerImpl struct {
	log            logr.Logger
	issuerURL      string
	client         *http.Client
	goOIDCProvider *gooidc.Provider
}

var _ Provider = (*providerImpl)(nil)

// NewOIDCProvider initializes an OIDC provider
func NewOIDCProvider(log logr.Logger, issuerURL string, client *http.Client) Provider {
	return &providerImpl{
		log:       log,
		issuerURL: issuerURL,
		client:    client,
	}
}

// oidcProvider lazily initializes, memoizes, and returns the OIDC provider.
func (p *providerImpl) provider() (*gooidc.Provider, error) {
	if p.goOIDCProvider != nil {
		return p.goOIDCProvider, nil
	}
	prov, err := p.newGoOIDCProvider()
	if err != nil {
		return nil, err
	}
	p.goOIDCProvider = prov
	return p.goOIDCProvider, nil
}

// newGoOIDCProvider creates a new instance of go-oidc.Provider querying the well known oidc
// configuration path (http://{servername}/.well-known/openid-configuration)
func (p *providerImpl) newGoOIDCProvider() (*gooidc.Provider, error) {
	p.log.V(log.Debug1.AsInt()).Info("Initializing OIDC provider ", "issuer", p.issuerURL)
	ctx := gooidc.ClientContext(context.Background(), p.client)
	prov, err := gooidc.NewProvider(ctx, p.issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to query provider %q: %v", p.issuerURL, err)
	}
	s, _ := ParseConfig(prov)
	p.log.V(log.Debug1.AsInt()).Info("OIDC supported scopes", "scopes", s.ScopesSupported)
	return prov, nil
}

func (p *providerImpl) Verify(ctx context.Context, clientID, tokenString string) (*gooidc.IDToken, error) {

	prov, err := p.provider()
	if err != nil {
		return nil, err
	}
	verifier := prov.Verifier(&gooidc.Config{ClientID: clientID})
	idToken, err := verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, err
	}
	return idToken, nil
}

func (p *providerImpl) Endpoint() (*oauth2.Endpoint, error) {
	prov, err := p.provider()
	if err != nil {
		return nil, err
	}
	endpoint := prov.Endpoint()
	return &endpoint, nil
}

// ParseConfig parses the OIDC Config into the concrete datastructure
func (p *providerImpl) ParseConfig() (*OIDCConfiguration, error) {
	prov, err := p.provider()
	if err != nil {
		return nil, err
	}
	return ParseConfig(prov)
}

// ParseConfig parses the OIDC Config into the concrete datastructure
func ParseConfig(provider *gooidc.Provider) (*OIDCConfiguration, error) {
	var conf OIDCConfiguration
	err := provider.Claims(&conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}
