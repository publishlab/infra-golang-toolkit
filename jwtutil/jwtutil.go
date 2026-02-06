//
// Utility for validating JSON Web Tokens
//

package jwtutil

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	jwtAuthzPrefix    = "Bearer "
	jwtAuthzPrefixLen = len(jwtAuthzPrefix)
)

type ValidateOpts struct {
	Authz          string
	KeyFunc        jwt.Keyfunc
	AssertSubject  string
	AssertAudience []string
	MaxExpiresAt   time.Duration
	MinIssuedAt    time.Duration
	MinNotBefore   time.Duration
}

type ClaimsPtr[T any] interface {
	jwt.Claims
	*T
}

func Validate[T any, PT ClaimsPtr[T]](opts *ValidateOpts) (*jwt.Token, error) {
	// Require bearer authorization scheme
	if (len(opts.Authz) <= jwtAuthzPrefixLen) || !strings.EqualFold(opts.Authz[:jwtAuthzPrefixLen], jwtAuthzPrefix) {
		return nil, fmt.Errorf("invalid authorization scheme")
	}

	// Parse and validate JWT
	token, err := jwt.ParseWithClaims(opts.Authz[jwtAuthzPrefixLen:], PT(new(T)), opts.KeyFunc)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Parse and validate claims
	claims, ok := token.Claims.(PT)
	if !ok {
		return nil, fmt.Errorf("unable to parse claims")
	}

	// Validate subject
	if opts.AssertSubject != "" {
		subjectClaim, err := claims.GetSubject()
		if err != nil {
			return nil, err
		}

		if (subjectClaim == "") || (subjectClaim != opts.AssertSubject) {
			return nil, fmt.Errorf("invalid token sub")
		}
	}

	// Validate audience
	if len(opts.AssertAudience) > 0 {
		audienceClaim, err := claims.GetAudience()
		if err != nil {
			return nil, err
		}

		if len(audienceClaim) == 0 {
			return nil, fmt.Errorf("invalid token sub")
		}

		for _, expected := range opts.AssertAudience {
			if !slices.Contains(audienceClaim, expected) {
				return nil, fmt.Errorf("invalid token sub")
			}
		}
	}

	// Validate expiration (maximum time)
	if opts.MaxExpiresAt > 0 {
		expirationClaim, err := claims.GetExpirationTime()
		if err != nil {
			return nil, err
		}

		if (expirationClaim == nil) || expirationClaim.After(time.Now().Add(opts.MaxExpiresAt)) {
			return nil, fmt.Errorf("invalid token exp")
		}
	}

	// Validate issued at (minimum time)
	if opts.MinIssuedAt > 0 {
		issuedAtClaim, err := claims.GetIssuedAt()
		if err != nil {
			return nil, err
		}

		if (issuedAtClaim == nil) || issuedAtClaim.Add(opts.MinIssuedAt).Before(time.Now()) {
			return nil, fmt.Errorf("invalid token iat")
		}
	}

	// Validate not before (min time)
	if opts.MinNotBefore > 0 {
		notBeforeClaim, err := claims.GetNotBefore()
		if err != nil {
			return nil, err
		}

		if (notBeforeClaim == nil) || notBeforeClaim.Add(opts.MinNotBefore).Before(time.Now()) {
			return nil, fmt.Errorf("invalid token nbf")
		}
	}

	return token, nil
}
