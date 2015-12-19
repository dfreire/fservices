package auth

import "github.com/dgrijalva/jwt-go"

type privateResetToken struct {
	email string
	lang  string
	key   string
}

func (self privateResetToken) toString(jwtKey string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["email"] = self.email
	token.Claims["lang"] = self.lang
	token.Claims["key"] = self.key
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

	resetToken = privateResetToken{
		token.Claims["email"].(string),
		token.Claims["lang"].(string),
		token.Claims["key"].(string),
	}
	return
}
