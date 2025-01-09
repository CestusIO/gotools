package authorizer

import (
	"context"

	"code.cestus.io/blaze"
)

// AuthorizerFunc defines signature of all authorization functions
type AuthorizerFunc func(ctx context.Context) error

// Authorizer defines the interface for an authorizer
type Authorizer interface {
	Authorize(ctx context.Context) error
}

// AuthorizerBuilder allows building a authorizer which uses multiple autorize functions in sequence
type AuthorizerBuilder interface {
	AddAuthorizer(authorizer ...AuthorizerFunc)
	Build() Authorizer
}

type authorizerBuilder struct {
	authorizers []AuthorizerFunc
}

func (s *authorizerBuilder) AddAuthorizer(authorizer ...AuthorizerFunc) {
	s.authorizers = append(s.authorizers, authorizer...)
}

func (s *authorizerBuilder) Build() Authorizer {
	return &authorizer{
		authorizers: s.authorizers,
	}
}

// NewAuthorizerBuilder creates a new AuthorizerBuilder
func NewAuthorizerBuilder() AuthorizerBuilder {
	return &authorizerBuilder{}
}

type authorizer struct {
	authorizers []AuthorizerFunc
}

// Authorize calls the authorization function for all registered authorizers
func (s authorizer) Authorize(ctx context.Context) error {
	for _, a := range s.authorizers {
		err := a(ctx)
		if err != nil {
			return blaze.ErrorPermissionDenied(err.Error())
		}
	}
	return nil
}

// AuthorizeWith is a conveniece function to allow a 1 line build and authorization
func AuthorizeWith(ctx context.Context, config Config, authorizer ...AuthorizerFunc) error {
	if config.Disabled {
		return nil
	}
	ab := authorizerBuilder{}
	ab.AddAuthorizer(authorizer...)
	return ab.Build().Authorize(ctx)
}
