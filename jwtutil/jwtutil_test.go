package jwtutil

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

type TestClaims struct {
	CustomClaim string `json:"custom_claim"`
	jwt.RegisteredClaims
}

var (
	goodSecret = []byte("correct-secret-key")
	badSecret  = []byte("wrong-secret-key")
)

func createTestAuthz(claims jwt.Claims, secret []byte) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(secret)
	return "Bearer " + tokenString
}

func testKeyFunc(secret []byte) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		return secret, nil
	}
}

func TestValidateToken(t *testing.T) {
	now := time.Now()
	claims := &TestClaims{
		CustomClaim: "test-value",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			Audience:  jwt.ClaimStrings{"test", "kake"},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token, err := Validate[TestClaims](&ValidateOpts{
		Authz:   createTestAuthz(claims, goodSecret),
		KeyFunc: testKeyFunc(goodSecret),
	})

	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.True(t, token.Valid)
}

func TestInvalidAuthorizations(t *testing.T) {
	tests := []string{
		"",
		"token-without-bearer",
		"Basic dXNlcjpwYXNz",
		"Bearer",
		"Bearer ",
	}

	for _, authz := range tests {
		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:   authz,
			KeyFunc: testKeyFunc(goodSecret),
		})

		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "invalid authorization scheme")
	}
}

func TestInvalidTokenFormat(t *testing.T) {
	token, err := Validate[TestClaims](&ValidateOpts{
		Authz:   "Bearer invalid.token.format",
		KeyFunc: testKeyFunc(goodSecret),
	})

	assert.Error(t, err)
	assert.Nil(t, token)
}

func TestInvalidSignature(t *testing.T) {
	now := time.Now()
	claims := &TestClaims{
		CustomClaim: "test-value",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}

	token, err := Validate[TestClaims](&ValidateOpts{
		Authz:   createTestAuthz(claims, badSecret),
		KeyFunc: testKeyFunc(goodSecret),
	})

	assert.Error(t, err)
	assert.Nil(t, token)
}

func TestExpiredToken(t *testing.T) {
	now := time.Now()
	claims := &TestClaims{
		CustomClaim: "test-value",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Minute)),
		},
	}

	token, err := Validate[TestClaims](&ValidateOpts{
		Authz:   createTestAuthz(claims, goodSecret),
		KeyFunc: testKeyFunc(goodSecret),
	})

	assert.Error(t, err)
	assert.Nil(t, token)
}

func TestPrematureToken(t *testing.T) {
	now := time.Now()
	claims := &TestClaims{
		CustomClaim: "test-value",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(now.Add(2 * time.Hour)),
			NotBefore: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}

	token, err := Validate[TestClaims](&ValidateOpts{
		Authz:   createTestAuthz(claims, goodSecret),
		KeyFunc: testKeyFunc(goodSecret),
	})

	assert.Error(t, err)
	assert.Nil(t, token)
}

func TestAssertSubject(t *testing.T) {
	now := time.Now()

	t.Run("valid subject", func(t *testing.T) {
		claims := &TestClaims{
			CustomClaim: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "user123",
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}

		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:         createTestAuthz(claims, goodSecret),
			KeyFunc:       testKeyFunc(goodSecret),
			AssertSubject: "user123",
		})

		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.True(t, token.Valid)
	})

	t.Run("invalid subject", func(t *testing.T) {
		claims := &TestClaims{
			CustomClaim: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "user123",
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}

		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:         createTestAuthz(claims, goodSecret),
			KeyFunc:       testKeyFunc(goodSecret),
			AssertSubject: "user456",
		})

		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "invalid token sub")
	})

	t.Run("empty subject", func(t *testing.T) {
		claims := &TestClaims{
			CustomClaim: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "",
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}

		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:         createTestAuthz(claims, goodSecret),
			KeyFunc:       testKeyFunc(goodSecret),
			AssertSubject: "user123",
		})

		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "invalid token sub")
	})
}

func TestAssertAudience(t *testing.T) {
	now := time.Now()

	t.Run("valid single audience", func(t *testing.T) {
		claims := &TestClaims{
			CustomClaim: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				Audience:  jwt.ClaimStrings{"test", "kake"},
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}

		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:          createTestAuthz(claims, goodSecret),
			KeyFunc:        testKeyFunc(goodSecret),
			AssertAudience: []string{"test"},
		})

		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.True(t, token.Valid)
	})

	t.Run("valid multiple audiences", func(t *testing.T) {
		claims := &TestClaims{
			CustomClaim: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				Audience:  jwt.ClaimStrings{"test", "kake", "prod"},
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}

		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:          createTestAuthz(claims, goodSecret),
			KeyFunc:        testKeyFunc(goodSecret),
			AssertAudience: []string{"test", "kake"},
		})

		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.True(t, token.Valid)
	})

	t.Run("missing expected audience", func(t *testing.T) {
		claims := &TestClaims{
			CustomClaim: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				Audience:  jwt.ClaimStrings{"test"},
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}

		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:          createTestAuthz(claims, goodSecret),
			KeyFunc:        testKeyFunc(goodSecret),
			AssertAudience: []string{"test", "missing"},
		})

		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "invalid token sub")
	})

	t.Run("empty audience", func(t *testing.T) {
		claims := &TestClaims{
			CustomClaim: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				Audience:  jwt.ClaimStrings{},
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}

		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:          createTestAuthz(claims, goodSecret),
			KeyFunc:        testKeyFunc(goodSecret),
			AssertAudience: []string{"test"},
		})

		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "invalid token sub")
	})
}

func TestMaxExpiresAt(t *testing.T) {
	now := time.Now()

	t.Run("valid expiration", func(t *testing.T) {
		claims := &TestClaims{
			CustomClaim: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Minute)),
			},
		}

		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:        createTestAuthz(claims, goodSecret),
			KeyFunc:      testKeyFunc(goodSecret),
			MaxExpiresAt: time.Hour,
		})

		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.True(t, token.Valid)
	})

	t.Run("expiration over limit", func(t *testing.T) {
		claims := &TestClaims{
			CustomClaim: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}

		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:        createTestAuthz(claims, goodSecret),
			KeyFunc:      testKeyFunc(goodSecret),
			MaxExpiresAt: time.Minute,
		})

		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "invalid token exp")
	})

	t.Run("missing expiration claim", func(t *testing.T) {
		claims := &TestClaims{
			CustomClaim: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: nil,
			},
		}

		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:        createTestAuthz(claims, goodSecret),
			KeyFunc:      testKeyFunc(goodSecret),
			MaxExpiresAt: time.Hour,
		})

		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "invalid token exp")
	})
}

func TestMinIssuedAt(t *testing.T) {
	now := time.Now()

	t.Run("valid issued at", func(t *testing.T) {
		claims := &TestClaims{
			CustomClaim: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(now.Add(-30 * time.Minute)),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}

		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:       createTestAuthz(claims, goodSecret),
			KeyFunc:     testKeyFunc(goodSecret),
			MinIssuedAt: time.Hour,
		})

		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.True(t, token.Valid)
	})

	t.Run("stale issued at", func(t *testing.T) {
		claims := &TestClaims{
			CustomClaim: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}

		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:       createTestAuthz(claims, goodSecret),
			KeyFunc:     testKeyFunc(goodSecret),
			MinIssuedAt: time.Hour,
		})

		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "invalid token iat")
	})

	t.Run("missing issued at claim", func(t *testing.T) {
		claims := &TestClaims{
			CustomClaim: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  nil,
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}

		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:       createTestAuthz(claims, goodSecret),
			KeyFunc:     testKeyFunc(goodSecret),
			MinIssuedAt: time.Hour,
		})

		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "invalid token iat")
	})
}

func TestMinNotBefore(t *testing.T) {
	now := time.Now()

	t.Run("valid not before", func(t *testing.T) {
		claims := &TestClaims{
			CustomClaim: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Minute)),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}

		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:        createTestAuthz(claims, goodSecret),
			KeyFunc:      testKeyFunc(goodSecret),
			MinNotBefore: time.Hour,
		})

		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.True(t, token.Valid)
	})

	t.Run("stale not before", func(t *testing.T) {
		claims := &TestClaims{
			CustomClaim: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				NotBefore: jwt.NewNumericDate(now.Add(-2 * time.Hour)),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}

		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:        createTestAuthz(claims, goodSecret),
			KeyFunc:      testKeyFunc(goodSecret),
			MinNotBefore: time.Hour,
		})

		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "invalid token nbf")
	})

	t.Run("missing not before claim", func(t *testing.T) {
		claims := &TestClaims{
			CustomClaim: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				NotBefore: nil,
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}

		token, err := Validate[TestClaims](&ValidateOpts{
			Authz:        createTestAuthz(claims, goodSecret),
			KeyFunc:      testKeyFunc(goodSecret),
			MinNotBefore: time.Hour,
		})

		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "invalid token nbf")
	})
}

func TestAllAssertions(t *testing.T) {
	now := time.Now()
	claims := &TestClaims{
		CustomClaim: "test-value",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			Audience:  jwt.ClaimStrings{"test", "kake"},
			ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now.Add(-15 * time.Minute)),
			NotBefore: jwt.NewNumericDate(now.Add(-15 * time.Minute)),
		},
	}

	token, err := Validate[TestClaims](&ValidateOpts{
		Authz:          createTestAuthz(claims, goodSecret),
		KeyFunc:        testKeyFunc(goodSecret),
		AssertSubject:  "user123",
		AssertAudience: []string{"test"},
		MaxExpiresAt:   time.Hour,
		MinIssuedAt:    30 * time.Minute,
		MinNotBefore:   30 * time.Minute,
	})

	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.True(t, token.Valid)
}

func TestAllClaims(t *testing.T) {
	now := time.Now()
	claims := &TestClaims{
		CustomClaim: "test-value",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   "user123",
			Audience:  jwt.ClaimStrings{"test", "kake"},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now.Add(-time.Hour)),
		},
	}

	token, err := Validate[TestClaims](&ValidateOpts{
		Authz:   createTestAuthz(claims, goodSecret),
		KeyFunc: testKeyFunc(goodSecret),
	})

	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.True(t, token.Valid)

	parsedClaims, ok := token.Claims.(*TestClaims)
	assert.True(t, ok)
	assert.Equal(t, "test-value", parsedClaims.CustomClaim)
	assert.Equal(t, "user123", parsedClaims.Subject)
	assert.Equal(t, "test-issuer", parsedClaims.Issuer)
	assert.Contains(t, parsedClaims.Audience, "test")
	assert.Contains(t, parsedClaims.Audience, "kake")
}

func TestKeyFuncError(t *testing.T) {
	now := time.Now()
	claims := &TestClaims{
		CustomClaim: "test-value",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}

	token, err := Validate[TestClaims](&ValidateOpts{
		Authz: createTestAuthz(claims, goodSecret),
		KeyFunc: func(token *jwt.Token) (any, error) {
			return nil, jwt.ErrTokenMalformed
		},
	})

	assert.Error(t, err)
	assert.Nil(t, token)
}

func TestKeyFuncNil(t *testing.T) {
	now := time.Now()
	claims := &TestClaims{
		CustomClaim: "test-value",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}

	token, err := Validate[TestClaims](&ValidateOpts{
		Authz:   createTestAuthz(claims, goodSecret),
		KeyFunc: nil,
	})

	assert.Error(t, err)
	assert.Nil(t, token)
}
