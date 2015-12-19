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

	confirmationToken = privateConfirmationToken{
		token.Claims["email"].(string),
		token.Claims["lang"].(string),
		token.Claims["key"].(string),
	}
	return
}

func createSessionToken(jwtKey, sessionId string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["sessionId"] = sessionId
	return token.SignedString([]byte(jwtKey))
}

func parseSessionToken(jwtKey, sessionToken string) (sessionId string, err error) {
	token, err := jwt.Parse(sessionToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtKey), nil
	})
	if err != nil {
		return
	}
	if !token.Valid {
		return
	}

	sessionId = token.Claims["sessionId"].(string)
	return
}

func createResetToken(jwtKey, email, lang, resetKey string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["email"] = email
	token.Claims["lang"] = lang
	token.Claims["resetKey"] = resetKey
	return token.SignedString([]byte(jwtKey))
}

func parseResetToken(jwtKey, resetToken string) (email, lang, resetKey string, err error) {
	token, err := jwt.Parse(resetToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtKey), nil
	})
	if err != nil {
		return
	}
	if !token.Valid {
		return
	}

	email = token.Claims["email"].(string)
	lang = token.Claims["lang"].(string)
	resetKey = token.Claims["resetKey"].(string)
	return
}
