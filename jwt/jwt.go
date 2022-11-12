package jwt

import (
	"context"
	"github.com/golang-jwt/jwt/v4"

	"github.com/tx7do/oidc-example"
	"github.com/tx7do/oidc-example/utils"
)

type Authenticator struct {
	signingMethod jwt.SigningMethod
	keyFunc       jwt.Keyfunc
}

var _ authn.Authenticator = (*Authenticator)(nil)

func NewAuthenticator(key, alg string) (authn.Authenticator, error) {
	auth := &Authenticator{
		signingMethod: jwt.GetSigningMethod(alg),
		keyFunc: func(token *jwt.Token) (interface{}, error) {
			return []byte(key), nil
		},
	}

	if auth.signingMethod == nil {
		auth.signingMethod = jwt.SigningMethodHS256
	}

	return auth, nil
}

func (a *Authenticator) Authenticate(ctx context.Context) (*authn.AuthClaims, error) {
	tokenString, err := utils.AuthFromMD(ctx, utils.BearerWord, false)
	if err != nil {
		return nil, authn.ErrMissingBearerToken
	}

	token, err := a.parseToken(tokenString)
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
	if token.Method != a.signingMethod {
		return nil, authn.ErrUnsupportedSigningMethod
	}
	if token.Claims == nil {
		return nil, authn.ErrInvalidClaims
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, authn.ErrInvalidClaims
	}

	authClaims, err := utils.MapClaimsToAuthClaims(claims)
	if err != nil {
		return nil, err
	}

	return authClaims, nil
}

func (a *Authenticator) parseToken(token string) (*jwt.Token, error) {
	if a.keyFunc == nil {
		return nil, authn.ErrMissingKeyFunc
	}

	return jwt.Parse(token, a.keyFunc)
}

func (a *Authenticator) generateToken(token *jwt.Token) (string, error) {
	if a.keyFunc == nil {
		return "", authn.ErrMissingKeyFunc
	}

	key, err := a.keyFunc(token)
	if err != nil {
		return "", authn.ErrGetKeyFailed
	}
	tokenStr, err := token.SignedString(key)
	if err != nil {
		return "", authn.ErrSignTokenFailed
	}

	return tokenStr, nil
}

func (a *Authenticator) CreateIdentity(ctx context.Context, claims authn.AuthClaims) (string, error) {
	token := jwt.NewWithClaims(a.signingMethod, utils.AuthClaimsToJwtClaims(claims))

	tokenStr, err := a.generateToken(token)
	if err != nil {
		return "", err
	}

	utils.MDWithAuth(ctx, utils.BearerWord, tokenStr, false)

	return tokenStr, nil
}

func (a *Authenticator) Close() {}
