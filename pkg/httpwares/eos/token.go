package eos

import (
	"context"

	"code.cestus.io/blaze"
	"code.cestus.io/libs/gotools/pkg/authorizer"
	"code.cestus.io/libs/gotypes/pkg/types"
)

const (
	XEosUser         = "x-eos-user"
	XEosAudience     = "x-eos-audience"
	XEosAppID        = "x-eos-app-id"
	XEosProductID    = "x-eos-product-id"
	XEosSandboxID    = "x-eos-sandbox-id"
	XEosDeploymentID = "x-eos-deployment-id"
	XAuthError       = "x-auth-error"
)

// Supplier is an interface that specifies methods to retrieve and store
// value for a key to an associated carrier.
// Get method retrieves the value for a given key.
// Set method stores the value for a given key.
type Supplier interface {
	Get(key string) string
	Set(key string, value string)
}

type eosToken struct{}

type EOSTokenContent struct {
	PlayerID     types.PlayerID        `json:"player_id,omitempty"`
	ProductID    types.EOSProductID    `json:"product_id,omitempty"`
	SandoxID     types.EOSSandboxID    `json:"sandox_id,omitempty"`
	DeploymentID types.EOSDeploymentID `json:"deployment_id,omitempty"`
}

var eosTokenID = &eosToken{}

// NewContext creates a context with token information
func NewContext(ctx context.Context, token EOSTokenContent) context.Context {
	return context.WithValue(ctx, eosTokenID, token)
}

// FromContext returns the token information from context
func FromContext(ctx context.Context) (EOSTokenContent, bool) {
	token, ok := ctx.Value(eosTokenID).(EOSTokenContent)
	return token, ok
}

// GetToken gets the EOSTokenContent from the supplier
func GetToken(s Supplier, p types.IDProvider) *EOSTokenContent {
	var playerID types.PlayerID
	var productID types.EOSProductID
	var sandboxID types.EOSSandboxID
	var deploymentID types.EOSDeploymentID
	p.FromStringOrNil(&playerID, s.Get(XEosUser))
	p.FromStringOrNil(&productID, s.Get(XEosProductID))
	p.FromStringOrNil(&sandboxID, s.Get(XEosSandboxID))
	p.FromStringOrNil(&deploymentID, s.Get(XEosDeploymentID))
	return &EOSTokenContent{
		PlayerID:     playerID,
		ProductID:    productID,
		SandoxID:     sandboxID,
		DeploymentID: deploymentID,
	}
}

func EOSTokenPlayerIDAuthorizer(playerID types.PlayerID) authorizer.AuthorizerFunc {
	fn := func(ctx context.Context) error {
		token, ok := FromContext(ctx)
		if !ok {
			return blaze.ErrorUnauthenticated("no token")
		}
		if token.PlayerID != playerID {
			// It could be that there is no valid token set or that its the wrong token and we want to seperate those cases
			if token.PlayerID != types.NilPlayerID {
				return blaze.ErrorPermissionDenied("profileID no match")
			}
			return blaze.ErrorUnauthenticated("no or invalid token")
		}
		return nil
	}
	return fn
}
