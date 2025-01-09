package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"code.cestus.io/libs/gotools/pkg/rand"
	"code.cestus.io/libs/log"
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
)

var ErrInvalidRedirectURL = fmt.Errorf("invalid return URL")

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeImplicit          = "implicit"
	ResponseTypeCode           = "code"
	StateCookieMaxAge          = time.Minute * 5
	StateCookieName            = "cestusio.oauthstate"
	AuthCookieName             = "cestusio.token"
)

type OIDCConfiguration struct {
	Issuer                 string   `json:"issuer"`
	ScopesSupported        []string `json:"scopes_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	GrantTypesSupported    []string `json:"grant_types_supported,omitempty"`
}

type ClaimsRequest struct {
	IDToken map[string]*Claim `json:"id_token"`
}

type Claim struct {
	Essential bool     `json:"essential,omitempty"`
	Value     string   `json:"value,omitempty"`
	Values    []string `json:"values,omitempty"`
}

type Token struct {
	// IDToken
	IDToken string
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`
	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`
	// Expiry is the optional expiration time of the access token.
	Expiry time.Time `json:"expiry,omitempty"`
}

type BearerTokenFormat struct {
	Name   string
	Length int
}
type ClientApp struct {
	log logr.Logger
	// OAuth2 client ID of this application
	clientID string
	// OAuth2 client secret of this application
	clientSecret string
	// Callback URL for OAuth2 responses (e.g. https://wombat.com/auth/callback)
	// redirectURI string
	// URL of the issuer
	issuerURL string
	// The URL endpoint at which the server is accessed.
	baseHRef string
	// client is the HTTP client which is used to query the IDp
	client *http.Client
	// secureCookie indicates if the cookie should be set with the Secure flag, meaning it should
	// only ever be sent over HTTPS. This value is inferred by the scheme of the redirectURI.
	secureCookie bool
	// provider is the OIDC provider
	provider          Provider
	config            *Config
	authCookieName    string
	stateCookieName   string
	bearerTokenFormat BearerTokenFormat
}

func GetScopesOrDefault(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{"openid", "profile", "email"}
	}
	return scopes
}

func GetRequestedIDTokenScopesOrDefault(requestedIdTokenScopes []string) []string {
	if len(requestedIdTokenScopes) == 0 {
		return []string{"groups"}
	}
	return requestedIdTokenScopes
}

type AuthType string

// ProvideClientApp will create a ClientApp and return an
// object which has HTTP handlers for handling the HTTP responses for login and callback
func ProvideClientApp(logger logr.Logger, config *Config, secrets *Secrets, authType AuthType) (*ClientApp, error) {
	// In the future here will be the place to get config values from other places then the config file
	// e.g. Vault or SecretStore
	// this will allow us to remove the needed knowledge of clientsecrets to users
	bearerTokenName := fmt.Sprintf("%s.%s", AuthCookieName, authType)
	a := ClientApp{
		log:             logger,
		clientID:        secrets.ClientID,
		clientSecret:    secrets.ClientSecret,
		issuerURL:       secrets.Issuer,
		baseHRef:        config.URL,
		config:          config,
		authCookieName:  fmt.Sprintf("%s.%s", AuthCookieName, authType),
		stateCookieName: fmt.Sprintf("%s.%s", StateCookieName, authType),
		bearerTokenFormat: BearerTokenFormat{
			Name:   bearerTokenName,
			Length: len(bearerTokenName),
		},
	}
	a.log.V(log.Debug1.AsInt()).Info("Creating client app", "app", a.clientID)
	u, err := url.Parse(config.URL)
	if err != nil {
		return nil, fmt.Errorf("parse redirect-uri: %v", err)
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	a.client = &http.Client{
		Transport: transport,
	}

	a.provider = NewOIDCProvider(logger, a.issuerURL, a.client)
	a.secureCookie = bool(u.Scheme == "https")
	return &a, nil
}

func (a *ClientApp) oauth2Config(scopes []string, redirectUrl string) (*oauth2.Config, error) {
	endpoint, err := a.provider.Endpoint()
	if err != nil {
		return nil, err
	}
	return &oauth2.Config{
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		Endpoint:     *endpoint,
		Scopes:       scopes,
		RedirectURL:  redirectUrl,
	}, nil
}

// generateAppState creates an app state nonce
func (a *ClientApp) generateAppState(returnURL string, w http.ResponseWriter) (string, error) {
	// According to the spec (https://www.rfc-editor.org/rfc/rfc6749#section-10.10), this must be guessable with
	// probability <= 2^(-128). The following call generates one of 52^24 random strings, ~= 2^136 possibilities.
	randStr, err := rand.String(24)
	if err != nil {
		return "", fmt.Errorf("failed to generate app state: %w", err)
	}
	if returnURL == "" {
		returnURL = a.baseHRef
	}
	cookieValue := fmt.Sprintf("%s:%s", randStr, returnURL)

	http.SetCookie(w, &http.Cookie{
		Name:     a.StateCookieName(),
		Value:    cookieValue,
		Expires:  time.Now().Add(StateCookieMaxAge),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   a.secureCookie,
	})
	return randStr, nil
}

func (a *ClientApp) verifyAppState(r *http.Request, w http.ResponseWriter, state string) (string, error) {
	c, err := r.Cookie(a.StateCookieName())
	if err != nil {
		return "", err
	}
	cookieVal := c.Value
	redirectURL := a.baseHRef
	parts := strings.SplitN(cookieVal, ":", 2)
	if len(parts) == 2 && parts[1] != "" {
		if !isValidRedirectURL(parts[1], []string{a.config.URL, a.baseHRef}) {
			sanitizedUrl := parts[1]
			if len(sanitizedUrl) > 100 {
				sanitizedUrl = sanitizedUrl[:100]
			}
			a.log.V(log.Error.AsInt()).Info("Failed to verify app state - got invalid redirectURL", "url", sanitizedUrl)
			return "", fmt.Errorf("failed to verify app state: %w", ErrInvalidRedirectURL)
		}
		redirectURL = parts[1]
	}
	if parts[0] != state {
		return "", fmt.Errorf("invalid state in '%s' cookie", a.CookieName())
	}
	// set empty cookie to clear it
	http.SetCookie(w, &http.Cookie{
		Name:     a.StateCookieName(),
		Value:    "",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   a.secureCookie,
	})
	return redirectURL, nil
}

// isValidRedirectURL checks whether the given redirectURL matches on of the
// allowed URLs to redirect to.
//
// In order to be considered valid,the protocol and host (including port) have
// to match and if allowed path is not "/", redirectURL's path must be within
// allowed URL's path.
func isValidRedirectURL(redirectURL string, allowedURLs []string) bool {
	if redirectURL == "" {
		return true
	}
	r, err := url.Parse(redirectURL)
	if err != nil {
		return false
	}
	// We consider empty path the same as "/" for redirect URL
	if r.Path == "" {
		r.Path = "/"
	}
	// Prevent CRLF in the redirectURL
	if strings.ContainsAny(r.Path, "\r\n") {
		return false
	}
	for _, baseURL := range allowedURLs {
		b, err := url.Parse(baseURL)
		if err != nil {
			continue
		}
		// We consider empty path the same as "/" for allowed URL
		if b.Path == "" {
			b.Path = "/"
		}
		// scheme and host are mandatory to match.
		if b.Scheme == r.Scheme && b.Host == r.Host {
			// If path of redirectURL and allowedURL match, redirectURL is allowed
			//if b.Path == r.Path {
			//	return true
			//}
			// If path of redirectURL is within allowed URL's path, redirectURL is allowed
			if strings.HasPrefix(path.Clean(r.Path), b.Path) {
				return true
			}
		}
	}
	// No match - redirect URL is not allowed
	return false
}

func (a ClientApp) buildRedirectUrl(r *http.Request, p string) string {
	// rebuild url if not configured
	var redirectUrl string
	if len(a.config.URL) == 0 {
		if strings.Contains(r.Host, "localhost") {
			redirectUrl = "http://" + path.Join(r.Host, p)
		} else {
			redirectUrl = "https://" + path.Join(r.Host, p)
		}
	} else {
		redirectUrl = path.Join(a.config.URL, p)
	}
	return redirectUrl
}

// HandleLogin formulates the proper OAuth2 URL (auth code or implicit) and redirects the user to
// the IDp login & consent page
func (a *ClientApp) HandleLogin() func(w http.ResponseWriter, r *http.Request) {
	p := "/auth/callback"
	if len(a.config.URL) != 0 {
		p = path.Join(a.config.URL, p)
	}
	return a.handleLogin(p)
}

// HandleToken formulates the proper OAuth2 URL (auth code or implicit) and redirects the user to
// the IDp login & consent page
func (a *ClientApp) HandleToken() func(w http.ResponseWriter, r *http.Request) {
	p := "/auth/tokencallback"
	if len(a.config.URL) != 0 {
		p = path.Join(a.config.URL, p)
	}

	return a.handleLogin(p)
}
func (a *ClientApp) handleLogin(url string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		oidcConf, err := a.provider.ParseConfig()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var opts []oauth2.AuthCodeOption
		scopes := a.config.Scopes
		claims := make(map[string]*Claim)
		for _, rs := range GetRequestedIDTokenScopesOrDefault(a.config.RequestedIDTokenClaims) {
			claim := Claim{
				Essential: true,
			}
			claims[rs] = &claim
		}
		opts = AppendClaimsAuthenticationRequestParameter(a.log, opts, claims)
		oauth2Config, err := a.oauth2Config(GetScopesOrDefault(scopes), a.buildRedirectUrl(r, url))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		returnURL := r.FormValue("return_url")
		// Check if return_url is valid, otherwise abort processing

		if !isValidRedirectURL(returnURL, []string{url}) {
			http.Error(w, "Invalid redirect URL: the protocol and host (including port) must match and the path must be within allowed URLs if provided", http.StatusBadRequest)
			return
		}
		stateNonce, err := a.generateAppState(returnURL, w)
		if err != nil {
			a.log.V(log.Error.AsInt()).Info("Failed to initiate login flow", "error", err)
			http.Error(w, "Failed to initiate login flow", http.StatusInternalServerError)
			return
		}
		grantType := InferGrantType(oidcConf)
		var url string
		switch grantType {
		case GrantTypeAuthorizationCode:
			url = oauth2Config.AuthCodeURL(stateNonce, opts...)
		case GrantTypeImplicit:
			url, err = ImplicitFlowURL(oauth2Config, stateNonce, opts...)
			if err != nil {
				a.log.V(log.Error.AsInt()).Info("Failed to initiate implicit login flow", "error", err)
				http.Error(w, "Failed to initiate implicit login flow", http.StatusInternalServerError)
				return
			}
		default:
			http.Error(w, fmt.Sprintf("Unsupported grant type: %v", grantType), http.StatusInternalServerError)
			return
		}
		a.log.V(log.Debug1.AsInt()).Info("Performing flow login", "type", grantType, "url", url)
		http.Redirect(w, r, url, http.StatusSeeOther)
	}
}

// HandleCallback is the callback handler for an OAuth2 login flow
func (a *ClientApp) HandleCallback() func(w http.ResponseWriter, r *http.Request) {
	p := "/auth/callback"
	if len(a.config.URL) != 0 {
		p = path.Join(a.config.URL, p)
	}
	return a.handleCallback(p)
}

func (a *ClientApp) handleCallback(url string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		oauth2Config, err := a.oauth2Config(nil, a.buildRedirectUrl(r, url))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		a.log.V(log.Debug1.AsInt()).Info("Callback", "url", r.URL)
		if errMsg := r.FormValue("error"); errMsg != "" {
			errorDesc := r.FormValue("error_description")
			http.Error(w, html.EscapeString(errMsg)+": "+html.EscapeString(errorDesc), http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		state := r.FormValue("state")
		if code == "" {
			// If code was not given, it implies implicit flow
			a.handleImplicitFlow(r, w, state)
			return
		}
		returnURL, err := a.verifyAppState(r, w, state)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ctx = gooidc.ClientContext(ctx, a.client)
		token, err := oauth2Config.Exchange(ctx, code)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to get token: %v", err), http.StatusInternalServerError)
			return
		}
		idTokenRAW, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "no id_token in token response", http.StatusInternalServerError)
			return
		}
		idToken, err := a.provider.Verify(ctx, a.clientID, idTokenRAW)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid session token: %v", err), http.StatusInternalServerError)
			return
		}
		path := "/"
		if a.baseHRef != "" {
			path = strings.TrimRight(strings.TrimLeft(a.baseHRef, "/"), "/")
		}
		cookiePath := fmt.Sprintf("path=/%s", path)
		flags := []string{cookiePath, "SameSite=lax", "httpOnly"}
		if a.secureCookie {
			flags = append(flags, "Secure")
		}
		var claims jwt.MapClaims
		err = idToken.Claims(&claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if idTokenRAW != "" {
			cookies, err := MakeCookieMetadata(a.CookieName(), idTokenRAW, flags...)
			if err != nil {
				claimsJSON, _ := json.Marshal(claims)
				http.Error(w, fmt.Sprintf("claims=%s, err=%v", claimsJSON, err), http.StatusInternalServerError)
				return
			}

			for _, cookie := range cookies {
				w.Header().Add("Set-Cookie", cookie)
			}
		}

		claimsJSON, _ := json.Marshal(claims)
		a.log.V(log.Debug1.AsInt()).Info("Web login successful", "claims", claimsJSON)
		http.Redirect(w, r, returnURL, http.StatusSeeOther)
	}
}

// HandleTokenCallback is the callback handler for an OAuth2 login flow returning a token
func (a *ClientApp) HandleTokenCallback() func(w http.ResponseWriter, r *http.Request) {
	p := "/auth/tokencallback"
	if len(a.config.URL) != 0 {
		p = path.Join(a.config.URL, p)
	}
	return a.handleTokenCallback(p)
}

func (a *ClientApp) handleTokenCallback(url string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		oauth2Config, err := a.oauth2Config(nil, a.buildRedirectUrl(r, url))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		a.log.V(log.Debug1.AsInt()).Info("Callback", "url", r.URL)
		if errMsg := r.FormValue("error"); errMsg != "" {
			errorDesc := r.FormValue("error_description")
			http.Error(w, html.EscapeString(errMsg)+": "+html.EscapeString(errorDesc), http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		state := r.FormValue("state")
		if code == "" {
			// If code was not given, it implies implicit flow
			a.handleImplicitFlow(r, w, state)
			return
		}
		_, err = a.verifyAppState(r, w, state)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ctx = gooidc.ClientContext(ctx, a.client)
		token, err := oauth2Config.Exchange(ctx, code)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to get token: %v", err), http.StatusInternalServerError)
			return
		}
		idTokenRAW, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "no id_token in token response", http.StatusInternalServerError)
			return
		}
		idToken, err := a.provider.Verify(ctx, a.clientID, idTokenRAW)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid session token: %v", err), http.StatusInternalServerError)
			return
		}
		path := "/"
		if a.baseHRef != "" {
			path = strings.TrimRight(strings.TrimLeft(a.baseHRef, "/"), "/")
		}
		cookiePath := fmt.Sprintf("path=/%s", path)
		flags := []string{cookiePath, "SameSite=lax", "httpOnly"}
		if a.secureCookie {
			flags = append(flags, "Secure")
		}
		var claims jwt.MapClaims
		err = idToken.Claims(&claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if idTokenRAW != "" {
			cookies, err := MakeCookieMetadata(a.CookieName(), idTokenRAW, flags...)
			if err != nil {
				claimsJSON, _ := json.Marshal(claims)
				http.Error(w, fmt.Sprintf("claims=%s, err=%v", claimsJSON, err), http.StatusInternalServerError)
				return
			}

			for _, cookie := range cookies {
				w.Header().Add("Set-Cookie", cookie)
			}
		}

		claimsJSON, _ := json.Marshal(claims)
		a.log.V(log.Debug1.AsInt()).Info("Web login successful", "claims", claimsJSON)
		t := Token{
			IDToken:      idTokenRAW,
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			Expiry:       token.Expiry,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(t)
	}
}

func (a *ClientApp) VerifyToken(ctx context.Context, tokenString string) (*gooidc.IDToken, error) {
	return a.provider.Verify(ctx, a.clientID, tokenString)
}

func (a *ClientApp) CookieName() string {
	return a.authCookieName
}

func (a *ClientApp) StateCookieName() string {
	return a.stateCookieName
}

func (a *ClientApp) BearerTokenFormat() BearerTokenFormat {
	return a.bearerTokenFormat
}

var implicitFlowTmpl = template.Must(template.New("implicit.html").Parse(`<script>
var hash = window.location.hash.substr(1);
var result = hash.split('&').reduce(function (result, item) {
	var parts = item.split('=');
	result[parts[0]] = parts[1];
	return result;
}, {});
var idToken = result['id_token'];
var state = result['state'];
var returnURL = "{{ .ReturnURL }}";
if (state != "" && returnURL == "") {
	window.location.href = window.location.href.split("#")[0] + "?state=" + result['state'] + window.location.hash;
} else if (returnURL != "") {
	document.cookie = "{{ .CookieName }}=" + idToken + "; path=/";
	window.location.href = returnURL;
}
</script>`))

// handleImplicitFlow completes an implicit OAuth2 flow. The id_token and state will be contained
// in the URL fragment. The javascript client first redirects to the callback URL, supplying the
// state nonce for verification, as well as looking up the return URL. Once verified, the client
// stores the id_token from the fragment as a cookie. Finally it performs the final redirect back to
// the return URL.
func (a *ClientApp) handleImplicitFlow(r *http.Request, w http.ResponseWriter, state string) {
	type implicitFlowValues struct {
		CookieName string
		ReturnURL  string
	}
	vals := implicitFlowValues{
		CookieName: a.CookieName(),
	}
	if state != "" {
		returnURL, err := a.verifyAppState(r, w, state)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		vals.ReturnURL = returnURL
	}
	renderTemplate(a.log, w, implicitFlowTmpl, vals)
}

// ImplicitFlowURL is an adaptation of oauth2.Config::AuthCodeURL() which returns a URL
// appropriate for an OAuth2 implicit login flow (as opposed to authorization code flow).
func ImplicitFlowURL(c *oauth2.Config, state string, opts ...oauth2.AuthCodeOption) (string, error) {
	opts = append(opts, oauth2.SetAuthURLParam("response_type", "id_token"))
	randString, err := rand.String(24)
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce for implicit flow URL: %w", err)
	}
	opts = append(opts, oauth2.SetAuthURLParam("nonce", randString))
	return c.AuthCodeURL(state, opts...), nil
}

// OfflineAccess returns whether or not 'offline_access' is a supported scope
func OfflineAccess(scopes []string) bool {
	if len(scopes) == 0 {
		// scopes_supported is a "RECOMMENDED" discovery claim, not a required
		// one. If missing, assume that the provider follows the spec and has
		// an "offline_access" scope.
		return true
	}
	// See if scopes_supported has the "offline_access" scope.
	for _, scope := range scopes {
		if scope == gooidc.ScopeOfflineAccess {
			return true
		}
	}
	return false
}

// InferGrantType infers the proper grant flow depending on the OAuth2 client config and OIDC configuration.
// Returns either: "authorization_code" or "implicit"
func InferGrantType(oidcConf *OIDCConfiguration) string {
	// Check the supported response types. If the list contains the response type 'code',
	// then grant type is 'authorization_code'. This is preferred over the implicit
	// grant type since refresh tokens cannot be issued that way.
	for _, supportedType := range oidcConf.ResponseTypesSupported {
		if supportedType == ResponseTypeCode {
			return GrantTypeAuthorizationCode
		}
	}

	// Assume implicit otherwise
	return GrantTypeImplicit
}

// AppendClaimsAuthenticationRequestParameter appends a OIDC claims authentication request parameter
// to `opts` with the `requestedClaims`
func AppendClaimsAuthenticationRequestParameter(logger logr.Logger, opts []oauth2.AuthCodeOption, requestedClaims map[string]*Claim) []oauth2.AuthCodeOption {
	if len(requestedClaims) == 0 {
		return opts
	}
	logger.V(log.Debug1.AsInt()).Info("RequestedClaims", "claims", requestedClaims)
	claimsRequestParameter, err := createClaimsAuthenticationRequestParameter(requestedClaims)
	if err != nil {
		logger.V(log.Debug1.AsInt()).Info("Failed to create OIDC claims authentication request parameter from config", "error", err)
		return opts
	}
	return append(opts, claimsRequestParameter)
}

func createClaimsAuthenticationRequestParameter(requestedClaims map[string]*Claim) (oauth2.AuthCodeOption, error) {
	claimsRequest := ClaimsRequest{IDToken: requestedClaims}
	claimsRequestRAW, err := json.Marshal(claimsRequest)
	if err != nil {
		return nil, err
	}
	return oauth2.SetAuthURLParam("claims", string(claimsRequestRAW)), nil
}

func renderTemplate(logger logr.Logger, w http.ResponseWriter, tmpl *template.Template, data interface{}) {
	err := tmpl.Execute(w, data)
	if err == nil {
		return
	}

	switch err := err.(type) {
	case *template.Error:
		// An ExecError guarantees that Execute has not written to the underlying reader.
		logger.V(log.Debug1.AsInt()).Info("Error rendering template", "name", tmpl.Name(), "error", err)

		http.Error(w, "Internal server error", http.StatusInternalServerError)
	default:
		// An error with the underlying write, such as the connection being
		// dropped. Ignore for now.
	}
}
