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

	rsaPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAukKbkMe3rGmzaArHUC49
3abT2jR0wv3GsLzfaymrBXqCQqYIcYwjf3QxdRKXaPRVKTV8CcGKvz79Z7i7r2G3
xBHS/Id5Qb0fybPd4bx33yHwRIBzfJvdl/avMPuqbnY41QCub+5k3aYR7h0XU/L9
qCUznMLc6Ve8rUFAjBt9+L+ePKPVo+R0l3m89rP6itJ3hyrckzJjGc4Nvv66jfwg
1vllClX2macXJ+l96wlMDEiQ3OXwesNzx+4jNqOKPBKvZTlk4oqAD7B9JUjtfBiu
AwrXTSgTB/AMBafaX+WwJPHMLbEPelEmlyJkOQF1mHDRKcd/Iz9vUxMrBWIzeu5e
cwIDAQAB
-----END PUBLIC KEY-----`

	ecdsaPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzvV3K2XH6YElbSKS/fts01w98JMg
9/tpd7PIrXt67MAXtDCs6WULbehJrgg6OhwirxkkpiVFCU/PGCe3EqkHmw==
-----END PUBLIC KEY-----`

	ed25519PublicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA2+VRi4Jnwi7qidWyxa/JdhwT+3bhCy1YtFxu2dcKHVE=
-----END PUBLIC KEY-----`
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

//
// Validate tests
//

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

func TestValidateInvalidAuthorizations(t *testing.T) {
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

func TestValidateInvalidTokenFormat(t *testing.T) {
	token, err := Validate[TestClaims](&ValidateOpts{
		Authz:   "Bearer invalid.token.format",
		KeyFunc: testKeyFunc(goodSecret),
	})

	assert.Error(t, err)
	assert.Nil(t, token)
}

func TestValidateInvalidSignature(t *testing.T) {
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

func TestValidateExpiredToken(t *testing.T) {
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

func TestValidatePrematureToken(t *testing.T) {
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

func TestValidateAssertSubject(t *testing.T) {
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

func TestValidateAssertAudience(t *testing.T) {
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
		assert.Contains(t, err.Error(), "invalid token aud")
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
		assert.Contains(t, err.Error(), "invalid token aud")
	})
}

func TestValidateMaxExpiresAt(t *testing.T) {
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

func TestValidateMinIssuedAt(t *testing.T) {
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

func TestValidateMinNotBefore(t *testing.T) {
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

func TestValidateAllAssertions(t *testing.T) {
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

func TestValidateAllClaims(t *testing.T) {
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

func TestValidateKeyFuncError(t *testing.T) {
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

func TestValidateKeyFuncNil(t *testing.T) {
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

//
// ParsePublicKey tests
//

func TestParsePublicKey(t *testing.T) {
	tests := []struct {
		name string
		pem  []byte
	}{
		{"rsa key", []byte(rsaPublicKey)},
		{"ecdsa key", []byte(ecdsaPublicKey)},
		{"ed25519 key", []byte(ed25519PublicKey)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParsePublicKey(tt.pem)

			assert.NoError(t, err)
			assert.NotNil(t, parsed)
			assert.NotEmpty(t, parsed.Kid)
			assert.NotNil(t, parsed.Public)

			// Verify kid
			assert.Len(t, parsed.Kid, 64)
			assert.Regexp(t, "^[0-9a-f]+$", parsed.Kid)
		})
	}

	t.Run("invalid pem", func(t *testing.T) {
		parsed, err := ParsePublicKey([]byte("not a valid PEM block"))

		assert.Error(t, err)
		assert.Nil(t, parsed)
		assert.Contains(t, err.Error(), "failed to decode pem block")
	})

	t.Run("empty input", func(t *testing.T) {
		parsed, err := ParsePublicKey([]byte(""))

		assert.Error(t, err)
		assert.Nil(t, parsed)
		assert.Contains(t, err.Error(), "failed to decode pem block")
	})

	t.Run("nil input", func(t *testing.T) {
		parsed, err := ParsePublicKey(nil)

		assert.Error(t, err)
		assert.Nil(t, parsed)
		assert.Contains(t, err.Error(), "failed to decode pem block")
	})

	t.Run("malformed pem structure", func(t *testing.T) {
		parsed, err := ParsePublicKey([]byte(`-----BEGIN PUBLIC KEY-----
this is not valid base64 data!@#$%
-----END PUBLIC KEY-----`))

		assert.Error(t, err)
		assert.Nil(t, parsed)
	})

	t.Run("wrong content type", func(t *testing.T) {
		// Valid PEM structure but contains a private key
		parsed, err := ParsePublicKey([]byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
VuNd9tybAgMBAAECggEAHw3MhWrXwPGWFdlv7dXVmBwPCxME9XvlLkm5LYzqGiMU
h5jPHLqGDtCHKMzM0Fj8qBGBjjOxMSPnQHJMEgxOVpPvP0JQKqTzVcvnVVz1pYQh
bTp3pLFkFCvdh4MQNuRqvR2iJr4Dz1LhH1jxhpQ1FzLFhZmxJJPxTJTZ7zzVoNPp
0P6U1pJmMH8cPYQfYRdGqU0FKPDQnPxOJDPQBvLFPwTjLQMvTqVZzRqVZYqYbPVo
QHZP0qZPvXQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQP
ZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQ
PZLMVPwTQHPwQKBgQDqPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZ
LMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQP
ZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQ
PZLMVPwTQHPwQKBgQDMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQ
HPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwT
QHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPw
TQHPwQPZLMVPwTQHPwQKBgHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPw
QPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHP
wQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQH
PwQPZLMVPwTQHPwQAoGAHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQP
ZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQ
PZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPw
QPZLMVPwTQHPwQCgYEAwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLM
VPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZL
MVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZLMVPwTQHPwQPZ
LMVPwTQHPwQ=
-----END PRIVATE KEY-----`))

		// x509.ParsePKIXPublicKey expects a public key
		assert.Error(t, err)
		assert.Nil(t, parsed)
	})

	t.Run("consistent fingerprint for same key", func(t *testing.T) {
		parsed1, err1 := ParsePublicKey([]byte(rsaPublicKey))
		parsed2, err2 := ParsePublicKey([]byte(rsaPublicKey))

		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.NotNil(t, parsed1)
		assert.NotNil(t, parsed2)
		assert.Equal(t, parsed1.Kid, parsed2.Kid)
	})

	t.Run("different fingerprints for different keys", func(t *testing.T) {
		parsed1, err1 := ParsePublicKey([]byte(rsaPublicKey))
		parsed2, err2 := ParsePublicKey([]byte(ecdsaPublicKey))

		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.NotNil(t, parsed1)
		assert.NotNil(t, parsed2)
		assert.NotEqual(t, parsed1.Kid, parsed2.Kid)
	})

	t.Run("pem with extra whitespace", func(t *testing.T) {
		parsed, err := ParsePublicKey([]byte("\n\n" + rsaPublicKey + "\n\n"))

		assert.NoError(t, err)
		assert.NotNil(t, parsed)
		assert.NotEmpty(t, parsed.Kid)
		assert.NotNil(t, parsed.Public)
	})
}
