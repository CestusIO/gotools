package bearer

import (
	"errors"
	"net/http"
	"strings"

	"code.cestus.io/blaze"
	"code.cestus.io/libs/gotools/pkg/oidc"
	"github.com/go-logr/logr"
)

var (
	ErrNoBearerHeaderFound        = errors.New("no bearer authorization header found")
	ErrNoAuthorizationCookieFound = errors.New("no authorization cookie found")
)

type ErrorHandler func(log logr.Logger, w http.ResponseWriter, r *http.Request, err error)
type JWTMiddlewareBuilder struct {
	tokenExtractors []func(r *http.Request) (string, error)
	clientApp       *oidc.ClientApp
	ErrorHandler    ErrorHandler
	logger          logr.Logger
}

func TokenVerifier(tm *JWTMiddlewareBuilder) func(next http.Handler) http.Handler {
	return tm.verifier
}

func Authenticator(tm *JWTMiddlewareBuilder) func(next http.Handler) http.Handler {
	return tm.authenticator
}

// ProvideJWTMiddlewareBuilder provides a jwtMiddleware
func ProvideJWTMiddlewareBuilder(clientApp *oidc.ClientApp, log logr.Logger) *JWTMiddlewareBuilder {
	j := &JWTMiddlewareBuilder{
		clientApp: clientApp,
		logger:    log,
	}
	// add default error handler
	j.ErrorHandler = j.defaultErrorHandler()
	// add default extractors
	j.tokenExtractors = []func(r *http.Request) (string, error){j.TokenFromHeader, j.TokenFromCookie(j.clientApp.CookieName())}
	return j
}

func (j JWTMiddlewareBuilder) defaultErrorHandler() func(log logr.Logger, w http.ResponseWriter, r *http.Request, err error) {
	return func(log logr.Logger, w http.ResponseWriter, r *http.Request, err error) {
		blaze.ServerWriteError(r.Context(), w, err, j.logger)
	}
}
func (j JWTMiddlewareBuilder) extractToken(r *http.Request) (string, error) {
	var token string
	var err error
	for _, tfn := range j.tokenExtractors {
		token, err = tfn(r)
		if err == nil {
			break
		}
	}
	if len(token) == 0 {
		return "", ErrNoTokenFound
	}
	return token, nil
}

func (j *JWTMiddlewareBuilder) verifier(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// extract
		var error blaze.Error
		token, err := j.extractToken(r)
		if err != nil {
			error = blaze.ErrorUnauthenticated(err.Error())
		}
		idToken, err := j.clientApp.VerifyToken(ctx, token)
		if err != nil && error == nil {
			error = blaze.ErrorUnauthenticated(err.Error())
		}
		ctx = NewContext(ctx, idToken, error)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}

func (j *JWTMiddlewareBuilder) authenticator(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		error, ok := ErrorFromContext(r.Context())
		if !ok {
			err := blaze.ErrorUnauthenticated(ErrNoTokenFound.Error())
			j.ErrorHandler(j.logger, w, r, err)
			return
		}
		if error != nil {
			j.ErrorHandler(j.logger, w, r, error)
			return
		}
		_, _, ok = TokenFromContext(r.Context())
		if !ok {
			return
		}
		// We got a previously validated token from context so pass through
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

// extractors

// TokenFromHeader tries to retreive the token string from the
// "Authorization" reqeust header: "Authorization: BEARER T".
func (j *JWTMiddlewareBuilder) TokenFromHeader(r *http.Request) (string, error) {
	// Get token from authorization header.
	bearer := r.Header.Get("Authorization")
	bearerLength := j.clientApp.BearerTokenFormat().Length + 1
	if len(bearer) > bearerLength && strings.EqualFold(bearer[0:j.clientApp.BearerTokenFormat().Length], j.clientApp.BearerTokenFormat().Name) {
		return bearer[bearerLength:], nil
	}
	return "", ErrNoBearerHeaderFound
}

// TokenFromCookie tries to retreive the token string from a cookie with the given name
func (j *JWTMiddlewareBuilder) TokenFromCookie(cookieName string) func(r *http.Request) (string, error) {
	return func(r *http.Request) (string, error) {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			return "", ErrNoAuthorizationCookieFound
		}
		return cookie.Value, nil
	}
}
