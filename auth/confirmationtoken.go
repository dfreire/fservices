package auth

import "github.com/dgrijalva/jwt-go"

type privateConfirmationToken struct {
	email string
	lang  string
	key   string
}

func (self privateConfirmationToken) toString(jwtKey string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["email"] = self.email
	token.Claims["lang"] = self.lang
	token.Claims["key"] = self.key
	return token.SignedString([]byte(jwtKey))
}

func parseConfirmationToken(jwtKey, confirmationTokenStr string) (confirmationToken privateConfirmationToken, err error) {
	token, err := jwt.Parse(confirmationTokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtKey), nil
	})
	if err != nil {
		return
	}
	if !token.Valid {
		return
	}

	confirmationToken.email = token.Claims["email"].(string)
	confirmationToken.lang = token.Claims["lang"].(string)
	confirmationToken.key = token.Claims["key"].(string)
	return
}
