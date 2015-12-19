package auth

import "github.com/dgrijalva/jwt-go"

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
