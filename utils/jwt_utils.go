package utils

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

type jwtService struct {
	secretKey string
	issuer    string
}

func NewJWTService() *jwtService {
	return &jwtService{
		secretKey: "akali",
		issuer:    "jwt-utils",
	}
}

type Claim struct {
	Id string `json:"id"`
	jwt.StandardClaims
}

func (s *jwtService) GenerateToken(id string) (string, error) {
	claim := &Claim{
		id,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 3).Unix(),
			Issuer:    s.issuer,
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)

	t, err := token.SignedString([]byte(s.secretKey))
	if err != nil {
		return "", err
	}

	return t, nil
}

func (s *jwtService) ValidateToken(token string) bool {
	_, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, isValid := t.Method.(*jwt.SigningMethodHMAC); !isValid {
			return nil, fmt.Errorf("invalid token: %v", token)
		}

		return []byte(s.secretKey), nil
	})

	return err == nil
}

func (s *jwtService) GetIDFromToken(token string) (string, error) {
	//method is called when token has been validated

	tokenParsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, isValid := t.Method.(*jwt.SigningMethodHMAC); !isValid {
			return nil, fmt.Errorf("invalid token: %v", token)
		}

		return []byte(s.secretKey), nil
	})
	if err != nil {
		return "", err
	}
	if claims, ok := tokenParsed.Claims.(jwt.MapClaims); ok && tokenParsed.Valid {
		id := claims["id"].(string)

		return id, nil
	}

	return "", err
}

func RemoveBearer(token string) (string, error) {
	const Bearer_schema = "Bearer "
	if token == "" || len(token) < 7 {
		return "", nil
	} else {
		return token[len(Bearer_schema):], nil
	}
}
