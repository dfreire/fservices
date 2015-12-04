package auth2

import (
	"errors"
	"time"

	"github.com/dfreire/fservices/mailer"
	"github.com/dfreire/fservices/util"
	"github.com/dgrijalva/jwt-go"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type Auth interface {
	Signup(appId, email, password, lang string) (confirmationToken string, err error)
	ResendConfirmationMail(appId, email, lang string) (confirmationToken string, err error)
	ConfirmSignup(confirmationToken string) error
	Signin(appId, email, password string) (sessionToken string, err error)
	Signout(sessionToken string) error
	ForgotPasword(appId, email, lang string) (resetToken string, err error)
	ResetPassword(resetToken, newPassword string) error
	// ChangePassword(userId, oldPassword, newPassword string) error
	// ChangeEmail(userId, password, newEmail string) error
	// GetAllUsers() ([]UserView, error)
	// GetUsersByAppId(appId string) ([]UserView, error)
	// CreateUser(appId, email, password string) error
	// ChangeUserPassword(userId, newPassword string) error
	// ChangeUserEmail(userId, newEmail string) error
	// RemoveUserById(userId string) error

	// RemoveExpiredSessions(appId strings, duration time.Duration) error
}

type UserView struct {
	Id    string
	AppId string
	Email string
}

type AuthConfig struct {
	JwtKey                  string
	MaxResetKeyAgeInMinutes int
	FromEmail               string
	ConfirmationEmail       AuthMailConfig
	ResetPasswordEmail      AuthMailConfig
}
type AuthMailConfig map[string]struct {
	Subject string
	Body    string
}

type authImpl struct {
	cfg    AuthConfig
	store  store
	mailer mailer.Mailer
}

func NewAuth(cfg AuthConfig, store store, mailer mailer.Mailer) authImpl {
	return authImpl{cfg, store, mailer}
}

func (self authImpl) Signup(appId, email, password, lang string) (confirmationToken string, err error) {
	confirmationKey, err := self.createUser(appId, email, password, lang, false)
	if err != nil {
		return
	}

	return self.sendConfirmationEmail(appId, email, lang, confirmationKey)
}

func (self authImpl) ResendConfirmationMail(appId, email, lang string) (confirmationToken string, err error) {
	confirmationKey, _, err := self.store.getUserConfirmation(appId, email)
	if err != nil {
		return
	}

	return self.sendConfirmationEmail(appId, email, lang, confirmationKey)
}

func (self authImpl) ConfirmSignup(confirmationToken string) error {
	appId, email, _, tokenConfirmationKey, err := self.parseConfirmationToken(confirmationToken)
	if err != nil {
		return err
	}

	confirmationKey, _, err := self.store.getUserConfirmation(appId, email)
	if err != nil {
		return err
	}

	if tokenConfirmationKey != confirmationKey {
		return errors.New("The confirmation key is not valid.")
	}

	return self.store.setUserConfirmedAt(appId, email, time.Now())
}

func (self authImpl) Signin(appId, email, password string) (sessionToken string, err error) {
	userId, hashedPass, confirmedAt, err := self.store.getUserPassword(appId, email)
	if err != nil {
		return
	}

	if confirmedAt.Equal(time.Time{}) {
		err = errors.New("The account has not been confirmed.")
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(password)); err != nil {
		return
	}

	sessionId := uuid.NewV4().String()
	sessionCreatedAt := time.Unix(time.Now().Unix(), 0)

	if err = self.store.createSession(sessionId, userId, sessionCreatedAt); err != nil {
		return
	}

	sessionToken, err = self.createSessionToken(sessionId, userId, sessionCreatedAt)
	return
}

func (self authImpl) Signout(sessionToken string) error {
	sessionId, _, _, err := self.parseSessionToken(sessionToken)
	if err != nil {
		return err
	}

	return self.store.removeSession(sessionId)
}

func (self authImpl) ForgotPasword(appId, email, lang string) (resetToken string, err error) {
	_, confirmedAt, err := self.store.getUserConfirmation(appId, email)
	if err != nil {
		return
	}

	if confirmedAt.Equal(time.Time{}) {
		err = errors.New("The account has not been confirmed.")
		return
	}

	resetKey := uuid.NewV4().String()

	err = self.store.setResetKey(appId, email, resetKey, time.Now())
	if err != nil {
		return
	}

	return self.sendResetPaswordEmail(appId, email, lang, resetKey)
}

func (self authImpl) ResetPassword(resetToken, newPassword string) error {
	appId, email, _, tokenResetKey, err := self.parseResetToken(resetToken)
	if err != nil {
		return err
	}

	resetKey, setResetKeyAt, err := self.store.getUserResetKey(appId, email)
	if err != nil {
		return err
	}

	if tokenResetKey != resetKey {
		return errors.New("The reset key is not valid.")
	}

	if time.Now().After(setResetKeyAt.Add(time.Duration(self.cfg.MaxResetKeyAgeInMinutes) * time.Minute)) {
		return errors.New("The reset key has expired.")
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return self.store.setUserHashedPass(appId, email, string(hashedPass))
}

func (self authImpl) createUser(appId, email, password, lang string, isConfirmed bool) (confirmationKey string, err error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	createdAt := time.Now()
	confirmedAt := time.Time{}

	if isConfirmed {
		confirmedAt = createdAt
	} else {
		confirmationKey = uuid.NewV4().String()
	}

	err = self.store.createUser(uuid.NewV4().String(), appId, email, string(hashedPass), lang, confirmationKey, createdAt, confirmedAt)
	return confirmationKey, err
}

func (self authImpl) sendConfirmationEmail(appId, email, lang, confirmationKey string) (confirmationToken string, err error) {
	confirmationToken, err = self.createConfirmationToken(appId, email, lang, confirmationKey)
	if err != nil {
		return
	}

	templateValues := struct{ ConfirmationToken string }{confirmationToken}
	body, err := util.RenderTemplate(self.cfg.ConfirmationEmail[lang].Body, templateValues)
	if err != nil {
		return
	}

	mail := mailer.Mail{
		From:    self.cfg.FromEmail,
		To:      []string{email},
		Subject: self.cfg.ConfirmationEmail[lang].Subject,
		Body:    body,
	}

	return confirmationToken, self.mailer.Send(mail)
}

func (self authImpl) sendResetPaswordEmail(appId, email, lang, resetKey string) (resetToken string, err error) {
	resetToken, err = self.createResetToken(appId, email, lang, resetKey)
	if err != nil {
		return
	}

	templateValues := struct{ ResetToken string }{resetToken}
	body, err := util.RenderTemplate(self.cfg.ResetPasswordEmail[lang].Body, templateValues)
	if err != nil {
		return
	}

	mail := mailer.Mail{
		From:    self.cfg.FromEmail,
		To:      []string{email},
		Subject: self.cfg.ResetPasswordEmail[lang].Subject,
		Body:    body,
	}

	return resetToken, self.mailer.Send(mail)
}

func (self authImpl) createConfirmationToken(appId, email, lang, confirmationKey string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["appId"] = appId
	token.Claims["email"] = email
	token.Claims["lang"] = lang
	token.Claims["confirmationKey"] = confirmationKey
	return token.SignedString([]byte(self.cfg.JwtKey))
}

func (self authImpl) parseConfirmationToken(confirmationToken string) (appId, email, lang, confirmationKey string, err error) {
	token, err := jwt.Parse(confirmationToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(self.cfg.JwtKey), nil
	})
	if err != nil {
		return
	}
	if !token.Valid {
		return
	}

	appId = token.Claims["appId"].(string)
	email = token.Claims["email"].(string)
	lang = token.Claims["lang"].(string)
	confirmationKey = token.Claims["confirmationKey"].(string)
	return
}

func (self authImpl) createSessionToken(id, userId string, createdAt time.Time) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["id"] = id
	token.Claims["userId"] = userId
	token.Claims["createdAt"] = createdAt.Unix()
	return token.SignedString([]byte(self.cfg.JwtKey))
}

func (self authImpl) parseSessionToken(sessionToken string) (id, userId string, createdAt time.Time, err error) {
	token, err := jwt.Parse(sessionToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(self.cfg.JwtKey), nil
	})
	if err != nil {
		return
	}
	if !token.Valid {
		return
	}

	id = token.Claims["id"].(string)
	userId = token.Claims["userId"].(string)
	createdAt = time.Unix(int64(token.Claims["createdAt"].(float64)), 0)
	return
}

func (self authImpl) createResetToken(appId, email, lang, resetKey string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["appId"] = appId
	token.Claims["email"] = email
	token.Claims["lang"] = lang
	token.Claims["resetKey"] = resetKey
	return token.SignedString([]byte(self.cfg.JwtKey))
}

func (self authImpl) parseResetToken(resetToken string) (appId, email, lang, resetKey string, err error) {
	token, err := jwt.Parse(resetToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(self.cfg.JwtKey), nil
	})
	if err != nil {
		return
	}
	if !token.Valid {
		return
	}

	appId = token.Claims["appId"].(string)
	email = token.Claims["email"].(string)
	lang = token.Claims["lang"].(string)
	resetKey = token.Claims["resetKey"].(string)
	return
}
