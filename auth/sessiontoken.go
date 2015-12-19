package auth

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type privateSessionToken struct {
	sessionId string
	userId    string
	createdAt time.Time
}

func (self privateSessionToken) toString(jwtKey string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["sessionId"] = self.sessionId
	token.Claims["userId"] = self.userId
	token.Claims["createdAt"] = self.createdAt.Unix()
	return token.SignedString([]byte(jwtKey))
}

func parseSessionToken(jwtKey, sessionTokenStr string) (sessionToken privateSessionToken, err error) {
	token, err := jwt.Parse(sessionTokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtKey), nil
	})
	if err != nil {
		return
	}
	if !token.Valid {
		return
	}

	sessionToken.sessionId = token.Claims["sessionId"].(string)
	sessionToken.userId = token.Claims["userId"].(string)
	sessionToken.createdAt = time.Unix(int64(token.Claims["createdAt"].(float64)), 0)
	return
}
