package utils

import (
	"bytes"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	authn "github.com/tx7do/oidc-example"
)

func AuthClaimsToJwtClaims(raw authn.AuthClaims) jwt.Claims {
	claims := jwt.MapClaims{
		"sub": raw.Subject,
	}

	var buffer bytes.Buffer
	count := len(raw.Scopes)
	idx := 0
	for scope := range raw.Scopes {
		buffer.WriteString(scope)
		if idx != count-1 {
			buffer.WriteString(" ")
		}
		idx++
	}
	str := buffer.String()
	if len(str) > 0 {
		claims["scope"] = buffer.String()
	}

	return claims
}

func MapClaimsToAuthClaims(rawClaims jwt.MapClaims) (*authn.AuthClaims, error) {
	// optional subject
	var subject = ""
	if subjectClaim, ok := rawClaims["sub"]; ok {
		if subject, ok = subjectClaim.(string); !ok {
			return nil, authn.ErrInvalidSubject
		}
	}

	claims := &authn.AuthClaims{
		Subject: subject,
		Scopes:  make(authn.ScopeSet),
	}

	// optional scopes
	if scopeKey, ok := rawClaims["scope"]; ok {
		if scope, ok := scopeKey.(string); ok {
			scopes := strings.Split(scope, " ")
			for _, s := range scopes {
				claims.Scopes[s] = true
			}
		}
	}

	return claims, nil
}

func JwtClaimsToAuthClaims(rawClaims jwt.Claims) (*authn.AuthClaims, error) {
	claims, ok := rawClaims.(jwt.MapClaims)
	if !ok {
		return nil, authn.ErrInvalidClaims
	}
	return MapClaimsToAuthClaims(claims)
}
