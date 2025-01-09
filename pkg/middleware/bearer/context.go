package bearer

import (
	"context"
	"errors"

	"code.cestus.io/blaze"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v4"
)

// contextKey is the key used in the request
// context where the information from a
// validated JWT will be stored.
// also used for the base of a bearer token error
type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "jwtauth context value " + k.name
}

var (
	TokenCtxKey     = &contextKey{"Token"}
	ErrorCtxKey     = &contextKey{"Error"}
	ErrNoTokenFound = errors.New("no token found")
)

// NewContext creates a new context from an existing one
// and adds the verified token and extraction error to the context
func NewContext(ctx context.Context, t *oidc.IDToken, err blaze.Error) context.Context {
	ctx = context.WithValue(ctx, TokenCtxKey, t)
	ctx = context.WithValue(ctx, ErrorCtxKey, err)
	return ctx
}

// ErrorFromContext returns the error from the context
// It returns nil, ok when there was no error stored or the error was nil
func ErrorFromContext(ctx context.Context) (blaze.Error, bool) {
	e := ctx.Value(ErrorCtxKey) //.(blaze.Error)
	// no error or nothing stored
	if e == nil {
		return nil, true
	}
	be, ok := e.(blaze.Error)
	if !ok {
		return nil, false
	}
	return be, true
}

// TokenFromContext gets the token and as convenience the parsed Claims from the context
func TokenFromContext(ctx context.Context) (*oidc.IDToken, jwt.MapClaims, bool) {
	idToken, ok := ctx.Value(TokenCtxKey).(*oidc.IDToken)
	if !ok {
		return nil, nil, false
	}

	var claims jwt.MapClaims

	if idToken != nil {
		err := idToken.Claims(&claims)
		if err != nil {
			return nil, nil, false
		}
	}

	return idToken, claims, true
}
