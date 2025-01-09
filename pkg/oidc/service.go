package oidc

import (
	"code.cestus.io/blaze"
	chi "github.com/go-chi/chi/v5"
	"github.com/go-logr/logr"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

type service struct {
	log                logr.Logger
	mux                *chi.Mux
	mountPath          string
	oauthConfig        *oauth2.Config
	oauthStateStringMs string
}

// Mux implements blaze.Service Mux
func (s *service) Mux() *chi.Mux {
	return s.mux
}

// MountPath implements blaze.service MountPath
func (s *service) MountPath() string {
	return s.mountPath
}

// check implementation guaranties
var _ blaze.Service = (*service)(nil)

func NewService(logger logr.Logger, config *Config, secrets *Secrets,  clientApp *ClientApp) *service {
	r := chi.NewRouter()
	router := service{
		log: logger,
		mux: r,
		oauthConfig: &oauth2.Config{
			ClientID:     secrets.ClientID,
			ClientSecret: secrets.ClientSecret,
			Endpoint:     microsoft.AzureADEndpoint(config.TenantID),
			Scopes:       config.Scopes,
		},
		oauthStateStringMs: "",
	}
	r.Get("/auth/login", clientApp.HandleLogin())
	r.Get("/auth/token", clientApp.HandleToken())
	r.Get("/auth/callback", clientApp.HandleCallback())
	r.Get("/auth/tokencallback", clientApp.HandleTokenCallback())
	return &router
}
