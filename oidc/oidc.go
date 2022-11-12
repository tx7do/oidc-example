package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/hashicorp/go-retryablehttp"

	"github.com/tx7do/oidc-example"
	"github.com/tx7do/oidc-example/utils"
)

var (
	jwkRefreshInterval, _ = time.ParseDuration("48h")
)

var _ authn.Authenticator = (*Authenticator)(nil)
var _ OIDCAuthenticator = (*Authenticator)(nil)

type Authenticator struct {
	IssuerURL string
	Audience  string

	JwksURI string
	JWKs    *keyfunc.JWKS

	signingMethod jwt.SigningMethod

	httpClient *http.Client
}

func NewAuthenticator(issuerURL, audience, alg string) (authn.Authenticator, error) {
	oidc := &Authenticator{
		IssuerURL:     issuerURL,
		Audience:      audience,
		httpClient:    retryablehttp.NewClient().StandardClient(),
		signingMethod: jwt.GetSigningMethod(alg),
	}

	if oidc.signingMethod == nil {
		oidc.signingMethod = jwt.SigningMethodRS256
	}

	if err := oidc.fetchKeys(); err != nil {
		return nil, err
	}

	//fmt.Println(oidc.JWKs.KIDs())

	return oidc, nil
}

func (oidc *Authenticator) parseToken(token string) (*jwt.Token, error) {
	return jwt.Parse(token, oidc.JWKs.Keyfunc)
}

func (oidc *Authenticator) Authenticate(requestContext context.Context) (*authn.AuthClaims, error) {
	tokenString, err := utils.AuthFromMD(requestContext, utils.BearerWord, false)
	if err != nil {
		return nil, authn.ErrMissingBearerToken
	}

	//jwtParser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	//
	//token, err := jwtParser.Parse(tokenString, func(token *jwt.Token) (any, error) {
	//	return oidc.JWKs.Keyfunc(token)
	//})
	//if err != nil {
	//	return nil, authn.ErrInvalidToken
	//}

	token, err := oidc.parseToken(tokenString)
	if err != nil {
		ve, ok := err.(*jwt.ValidationError)
		if !ok {
			return nil, authn.ErrUnauthenticated
		}
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return nil, authn.ErrInvalidToken
		}
		if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			return nil, authn.ErrTokenExpired
		}
		return nil, authn.ErrInvalidToken
	}

	if !token.Valid {
		return nil, authn.ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, authn.ErrInvalidClaims
	}

	if ok := claims.VerifyIssuer(oidc.IssuerURL, true); !ok {
		return nil, authn.ErrInvalidIssuer
	}

	if ok := claims.VerifyAudience(oidc.Audience, true); !ok {
		return nil, authn.ErrInvalidAudience
	}

	principal, err := utils.MapClaimsToAuthClaims(claims)
	if err != nil {
		return nil, err
	}

	return principal, nil
}

func (oidc *Authenticator) CreateIdentity(ctx context.Context, claims authn.AuthClaims) (string, error) {
	return "", nil
}

func (oidc *Authenticator) Close() {
	oidc.JWKs.EndBackground()
}

func (oidc *Authenticator) fetchKeys() error {
	oidcConfig, err := oidc.GetConfiguration()
	if err != nil {
		return fmt.Errorf("error fetching OIDC configuration: %w", err)
	}

	oidc.JwksURI = oidcConfig.JWKSURL

	jwks, err := oidc.GetKeys()
	if err != nil {
		return fmt.Errorf("error fetching OIDC keys: %w", err)
	}

	oidc.JWKs = jwks

	return nil
}

func (oidc *Authenticator) GetKeys() (*keyfunc.JWKS, error) {
	jwks, err := keyfunc.Get(oidc.JwksURI, keyfunc.Options{
		Client:          oidc.httpClient,
		RefreshInterval: jwkRefreshInterval,
	})
	if err != nil {
		return nil, fmt.Errorf("error fetching keys from %v: %w", oidc.JwksURI, err)
	}
	return jwks, nil
}

func (oidc *Authenticator) getDiscoveryUri() string {
	return strings.TrimSuffix(oidc.IssuerURL, "/") + "/.well-known/openid-configuration"
}

func (oidc *Authenticator) GetConfiguration() (*ProviderConfig, error) {
	wellKnown := oidc.getDiscoveryUri()
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("error forming request to get OIDC: %w", err)
	}

	res, err := oidc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error getting OIDC: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(res.Body)

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code getting OIDC: %v", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	oidcConfig := &ProviderConfig{}
	if err := json.Unmarshal(body, oidcConfig); err != nil {
		return nil, fmt.Errorf("failed parsing document: %w", err)
	}

	if oidcConfig.Issuer == "" {
		return nil, errors.New("missing issuer value")
	}

	if oidcConfig.JWKSURL == "" {
		return nil, errors.New("missing jwks_uri value")
	}

	return oidcConfig, nil
}
