package auth

import "github.com/dgrijalva/jwt-go"



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
