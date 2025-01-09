package eos

import (
	"net/http"

	"code.cestus.io/libs/gotypes/pkg/types"
)

func Middleware(idp types.IDProvider) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			token := GetToken(r.Header, idp)
			ctx = NewContext(ctx, *token)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}
