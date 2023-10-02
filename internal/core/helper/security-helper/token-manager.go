package helper

import (
	"crypto/ed25519"
	"errors"
	"encoding/base64"
	"time"
	"walls-identity-service/internal/core/domain/dto"
	helper "walls-identity-service/internal/core/helper/configuration-helper"

	"github.com/golang-jwt/jwt"
)

type TokenManager struct {
	tokenKey           string
	issuer             string
	duration           time.Duration
	signingAlgorithm   string
	audience           string
	revokedTokensStore *TokenBlacklist
}

type Claims struct {
	dto.CurrentUserDto
	jwt.StandardClaims
}

// NewTokenManager creates a new TokenManager.
func NewTokenManager() *TokenManager {
	duration, _ := time.ParseDuration(helper.ServiceConfiguration.Duration)

	return &TokenManager{
		tokenKey:         helper.ServiceConfiguration.TokenKey,
		issuer:           helper.ServiceConfiguration.Issuer,
		duration:         duration,
		signingAlgorithm: helper.ServiceConfiguration.SigningAlgorithm,
		audience:         helper.ServiceConfiguration.Audience,
	}
}

// GenerateToken generates a new JWT for a user.
func (tm *TokenManager) GenerateToken(c Claims) (string, error) {
    // Create the JWT claims
    claims := Claims{
        CurrentUserDto: c.CurrentUserDto,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: time.Now().Add(tm.duration).Unix(),
            Issuer:    tm.issuer,
            IssuedAt:  time.Now().Unix(),
        },
    }

    // var err error

    // If the signing algorithm is EdDSA
    if tm.signingAlgorithm == "EdDSA" {
        // Decode the base64-encoded private key from the environment
        decodedKey, err := base64.StdEncoding.DecodeString(tm.tokenKey)
        if err != nil {
            return "", err
        }

        privateKey := ed25519.PrivateKey(decodedKey)

        // Sign the JWT with the private key
        return jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(privateKey)
    }
        decodedKey, err := base64.StdEncoding.DecodeString(tm.tokenKey)
        if err != nil {
            return "", err
        }
        return jwt.NewWithClaims(getSigningMethod(tm.signingAlgorithm), claims).SignedString(decodedKey)
}

// ParseToken parses a JWT from a string, returning the claims.
func (tm *TokenManager) ParseToken(tokenStr string) (*Claims, error) {
	// Parse the token
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Make sure the token method conforms to the "signingAlgorithm"
		if alg, ok := token.Method.(*jwt.SigningMethodHMAC); !ok || alg != getSigningMethod(tm.signingAlgorithm) {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(tm.tokenKey), nil
	})

	if err != nil {
		return nil, err
	}

	// Validate the token and return the custom claims
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

// VerifyToken verifies the JWT.
func (tm *TokenManager) VerifyToken(tokenStr string) (bool, error) {
	// Parse the token
	claims, err := tm.ParseToken(tokenStr)
	if err != nil {
		return false, err
	}

	// Verify the token is not expired
	if claims.ExpiresAt < time.Now().Unix() {
		return false, errors.New("jwt is expired")
	}

	revoked, err := tm.revokedTokensStore.IsTokenRevoked(tokenStr)

	return revoked, err
}

// RevokeToken revokes a JWT.
func (tm *TokenManager) RevokeToken(token string) error {
	claims, err := tm.ParseToken(token)
	if err != nil {
		return err
	}

	remainingValidity := time.Until(time.Unix(claims.ExpiresAt, 0))
	if remainingValidity < 0 {
		remainingValidity = 0
	}

	return tm.revokedTokensStore.RevokeToken(token, remainingValidity)
}

// And a method to check if a token is revoked.
func (tm *TokenManager) IsTokenRevoked(tokenStr string) (bool, error) {
	return tm.revokedTokensStore.IsTokenRevoked(tokenStr)
}

func getSigningMethod(signingAlgorithm string) jwt.SigningMethod {
	switch signingAlgorithm {
	case "HS256":
		return jwt.SigningMethodHS256
	case "HS384":
		return jwt.SigningMethodHS384
	case "HS512":
		return jwt.SigningMethodHS512
	case "ES256":
		return jwt.SigningMethodES256
	case "ES384":
		return jwt.SigningMethodES384
	case "ES512":
		return jwt.SigningMethodES512
	case "RS256":
		return jwt.SigningMethodRS256
	case "RS384":
		return jwt.SigningMethodRS384
	case "RS512":
		return jwt.SigningMethodRS512
	case "PS256":
		return jwt.SigningMethodPS256
	case "PS384":
		return jwt.SigningMethodPS384
	case "PS512":
		return jwt.SigningMethodPS512
	case "EdDSA":
		return jwt.SigningMethodEdDSA
	default:
		return jwt.SigningMethodHS256
	}
}
