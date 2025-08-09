package token

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"mssngr/authErrors"
	"os"
	"time"
)

const (
	AccessCookieName  = "jwt_token_access"
	RefreshCookieName = "jwt_token_refresh"
)

type UserClaims struct {
	ID string `json:"id"`
	jwt.RegisteredClaims
}

func GenerateJWTTokens(id string) (string, string, time.Duration, time.Duration, error) {
	signedStringAccess, expAccess, err := GenerateJWTAccess(id)
	if err != nil {
		return "", "", 0, 0, err
	}
	signedStringRefresh, expRefresh, err := GenerateJWTRefresh(id)
	if err != nil {
		return "", "", 0, 0, err
	}

	return signedStringAccess, signedStringRefresh, expAccess, expRefresh, nil
}
func GenerateJWTAccess(id string) (string, time.Duration, error) {
	jwtKey := os.Getenv("JWT_SECRET")
	if jwtKey == "" {
		return "", 0, fmt.Errorf("environment variable JWT_SECRET is not set. Please define it before running the application")
	}

	var expAccess = time.Minute * 15

	var claimsAccess UserClaims

	claimsAccess.ID = id
	claimsAccess.ExpiresAt = jwt.NewNumericDate(time.Now().Add(expAccess))

	tokenAccess := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsAccess)

	signedStringAccess, err := tokenAccess.SignedString([]byte(jwtKey))
	if err != nil {
		return "", 0, authErrors.ErrInternal
	}

	return signedStringAccess, expAccess, nil
}
func GenerateJWTRefresh(id string) (string, time.Duration, error) {
	jwtKey := os.Getenv("JWT_SECRET")
	if jwtKey == "" {
		return "", 0, fmt.Errorf("environment variable JWT_SECRET is not set. Please define it before running the application")
	}

	var expRefresh = time.Hour * 24 * 15

	var claimsRefresh UserClaims

	claimsRefresh.ID = id
	claimsRefresh.ExpiresAt = jwt.NewNumericDate(time.Now().Add(expRefresh))

	tokenRefresh := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsRefresh)
	signedStringRefresh, err := tokenRefresh.SignedString([]byte(jwtKey))
	if err != nil {
		return "", 0, authErrors.ErrInternal
	}

	return signedStringRefresh, expRefresh, nil
}

func GenerateJWTResetPassword(id string) (string, time.Duration, error) {
	jwtKey := os.Getenv("JWT_SECRET")
	if jwtKey == "" {
		return "", 0, fmt.Errorf("environment variable JWT_SECRET is not set. Please define it before running the application")
	}

	var expRefresh = time.Minute * 5

	var claimsRefresh UserClaims

	claimsRefresh.ID = id
	claimsRefresh.ExpiresAt = jwt.NewNumericDate(time.Now().Add(expRefresh))

	tokenRefresh := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsRefresh)
	signedStringRefresh, err := tokenRefresh.SignedString([]byte(jwtKey))
	if err != nil {
		return "", 0, authErrors.ErrInternal
	}

	return signedStringRefresh, expRefresh, nil
}

func ParseJWT(jwtString string) (*jwt.Token, error) {
	jwtKey := os.Getenv("JWT_SECRET")
	if jwtKey == "" {
		return &jwt.Token{}, fmt.Errorf("environment variable JWT_SECRET is not set. Please define it before running the application")
	}

	token, err := jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtKey), nil
	})
	if err != nil {
		return &jwt.Token{}, err
	}
	return token, nil
}
func ParseJWTWithClaims(jwtString string) (*UserClaims, error) {
	jwtKey := os.Getenv("JWT_SECRET")
	if jwtKey == "" {
		return nil, fmt.Errorf("environment variable JWT_SECRET is not set. Please define it before running the application")
	}

	token, err := jwt.ParseWithClaims(jwtString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtKey), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, authErrors.ErrUnauthorized
}
