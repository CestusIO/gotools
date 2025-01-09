package s2sauth

import (
	"context"
	"encoding/json"

	"code.cestus.io/libs/gotools/pkg/clientware"
	"code.cestus.io/libs/gotools/pkg/kestrel"
	"code.cestus.io/libs/gotools/pkg/secrets"
	"github.com/zitadel/oidc/v3/pkg/client/profile"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"golang.org/x/oauth2"
)

type emptyTokenSource struct{}

func (ts emptyTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{}, nil
}
func ProvideS2STokensource(ctx context.Context, secretConf *secrets.Config, secrets *Secrets, conf *Config, kconf *kestrel.Config) (clientware.S2STokensource, error) {
	// When secrets are disabled we add a token source which does set empty tokens
	if !secretConf.Enabled {
		return &emptyTokenSource{}, nil
	}
	// the Key used by the tokensource is a json string so we have to reconstruct this.
	data, err := json.Marshal(secrets)
	if err != nil {
		return &emptyTokenSource{}, nil
	}
	return profile.NewJWTProfileTokenSourceFromKeyFileData(ctx, conf.Issuer, data, []string{"openid", "profile", client.ScopeProjectID(kconf.ZProjectID)})
}
