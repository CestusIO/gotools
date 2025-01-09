package authentication

import (
	"code.cestus.io/libs/gotools/pkg/middleware/bearer"
	"code.cestus.io/libs/gotools/pkg/oidc"
	"github.com/go-logr/logr"
)

type AdminMiddlewareBuilder bearer.JWTMiddlewareBuilder
type PlayerMiddlewareBuilder bearer.JWTMiddlewareBuilder
type S2SMiddlewareBuilder bearer.JWTMiddlewareBuilder

type AdminClientApp oidc.ClientApp
type PlayerClientApp oidc.ClientApp
type S2SClientApp oidc.ClientApp

type AuthMiddlewares struct {
	Admin  AdminMiddlewareBuilder
	Player PlayerMiddlewareBuilder
	S2S    S2SMiddlewareBuilder
}

func ProvideAdminClientApp(logger logr.Logger, config *Config, secrets *Secrets) (*AdminClientApp, error) {
	ca, err := oidc.ProvideClientApp(logger, config.AdminOIDCConfig, secrets.AdminOIDCSecrets, "admin")
	return (*AdminClientApp)(ca), err
}

// ProvideAdminMiddlewareBuilder provides a jwtMiddleware
func ProvideAdminMiddlewareBuilder(clientApp *AdminClientApp, log logr.Logger) *AdminMiddlewareBuilder {
	return (*AdminMiddlewareBuilder)(bearer.ProvideJWTMiddlewareBuilder((*oidc.ClientApp)(clientApp), log))
}

// ProvidePlayerMiddlewareBuilder provides a jwtMiddleware
func ProvidePlayerMiddlewareBuilder(clientApp *PlayerClientApp, log logr.Logger) *PlayerMiddlewareBuilder {
	return (*PlayerMiddlewareBuilder)(bearer.ProvideJWTMiddlewareBuilder((*oidc.ClientApp)(clientApp), log))
}

func ProvidePlayerClientApp(logger logr.Logger, config *Config, secrets *Secrets) (*PlayerClientApp, error) {
	ca, err := oidc.ProvideClientApp(logger, config.PlayerOIDCConfig, secrets.PlayerOIDCSecrets, "player")
	return (*PlayerClientApp)(ca), err
}

// ProvideS2SMiddlewareBuilder provides a jwtMiddleware
func ProvideS2SMiddlewareBuilder(clientApp *S2SClientApp, log logr.Logger) *S2SMiddlewareBuilder {
	return (*S2SMiddlewareBuilder)(bearer.ProvideJWTMiddlewareBuilder((*oidc.ClientApp)(clientApp), log))
}

func ProvideS2SClientApp(logger logr.Logger, config *Config, secrets *Secrets) (*S2SClientApp, error) {
	ca, err := oidc.ProvideClientApp(logger, config.S2SOIDCConfig, secrets.S2SOIDCSecrets, "s2s")
	return (*S2SClientApp)(ca), err
}

func ProvideAuthMiddlewares(admin *AdminMiddlewareBuilder, player *PlayerMiddlewareBuilder, s2s *S2SMiddlewareBuilder) (*AuthMiddlewares, error) {
	return &AuthMiddlewares{
		Admin:  *admin,
		Player: *player,
		S2S:    *s2s,
	}, nil
}
