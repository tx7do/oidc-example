package noop

import (
	"context"
	"github.com/tx7do/oidc-example"
)

type Authenticator struct{}

var _ authn.Authenticator = (*Authenticator)(nil)

func (n Authenticator) Authenticate(_ context.Context) (*authn.AuthClaims, error) {
	return &authn.AuthClaims{
		Subject: "",
		Scopes:  nil,
	}, nil
}

func (n Authenticator) CreateIdentity(_ context.Context, _ authn.AuthClaims) (string, error) {
	return "", nil
}

func (n Authenticator) Close() {}
