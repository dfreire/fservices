package auth

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type privateResetToken struct {
	email     string
	lang      string
	key       string
	createdAt time.Time
}

func (self privateResetToken) toString(jwtKey string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["email"] = self.email
	token.Claims["lang"] = self.lang
	token.Claims["key"] = self.key
	token.Claims["createdAt"] = self.createdAt.Unix()
	return token.SignedString([]byte(jwtKey))
}

func parseResetToken(jwtKey, resetTokenStr string) (resetToken privateResetToken, err error) {
	token, err := jwt.Parse(resetTokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtKey), nil
	})
	if err != nil {
		return
	}
	if !token.Valid {
		return
	}

	resetToken.email = token.Claims["email"].(string)
	resetToken.lang = token.Claims["lang"].(string)
	resetToken.key = token.Claims["key"].(string)
	resetToken.createdAt = time.Unix(int64(token.Claims["createdAt"].(float64)), 0)
	return
}
