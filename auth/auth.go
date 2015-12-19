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
	Signup(email, password, lang string) (confirmationToken string, err error)
	ResendConfirmationMail(email, lang string) (confirmationToken string, err error)
	ConfirmSignup(confirmationToken string) error
	Signin(email, password string) (sessionToken string, err error)
	ForgotPasword(email, lang string) (resetToken string, err error)
	ResetPassword(resetToken, newPassword string) error

	Signout(sessionToken string) error
	ChangePassword(sessionToken, oldPassword, newPassword string) error
	ChangeEmail(sessionToken, password, newEmail string) error

	GetUsers(adminKey string) ([]User, error)
	CreateUser(adminKey, email, password, lang string) error
	ChangeUserPassword(adminKey, userId, newPassword string) error
	ChangeUserEmail(adminKey, userId, newEmail string) error
	RemoveUser(adminKey, userId string) error

	RemoveUnconfirmedUsers(adminKey string) error
	// RemoveIdleSessions(adminKey string) error
	// RemoveExpiredResetKeys(adminKey string) error
}

type AuthConfig struct {
	AdminKey               string
	JwtKey                 string
	MaxUnconfirmedUsersAge string
	MaxIdleSessionAge      string
	MaxResetKeyAge         string
	FromEmail              string
	ConfirmationEmail      AuthMailConfig
	ResetPasswordEmail     AuthMailConfig
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

func (self authImpl) Signup(email, password, lang string) (confirmationToken string, err error) {
	confirmationKey, err := self.createUser(email, password, lang, false)
	if err != nil {
		return
	}

	return self.sendConfirmationEmail(email, lang, confirmationKey)
}

func (self authImpl) ResendConfirmationMail(email, lang string) (confirmationToken string, err error) {
	userId, err := self.store.getUserId(email)
	if err != nil {
		return
	}

	user, err := self.store.getUser(userId)
	if err != nil {
		return
	}

	return self.sendConfirmationEmail(email, lang, user.confirmationKey)
}

func (self authImpl) ConfirmSignup(confirmationToken string) error {
	email, _, tokenConfirmationKey, err := self.parseConfirmationToken(confirmationToken)
	if err != nil {
		return err
	}

	userId, err := self.store.getUserId(email)
	if err != nil {
		return err
	}

	user, err := self.store.getUser(userId)
	if err != nil {
		return err
	}

	if tokenConfirmationKey != user.confirmationKey {
		return errors.New("The confirmation key is not valid.")
	}

	return self.store.setUserConfirmedAt(userId, time.Now())
}

func (self authImpl) Signin(email, password string) (sessionToken string, err error) {
	userId, err := self.store.getUserId(email)
	if err != nil {
		return
	}

	user, err := self.store.getUser(userId)
	if err != nil {
		return
	}

	if user.confirmedAt.Equal(time.Time{}) {
		err = errors.New("The account has not been confirmed.")
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.hashedPass), []byte(password)); err != nil {
		return
	}

	sessionId := uuid.NewV4().String()
	sessionCreatedAt := time.Now()

	if err = self.store.createSession(sessionId, userId, sessionCreatedAt); err != nil {
		return
	}

	sessionToken, err = self.createSessionToken(sessionId)
	return
}

func (self authImpl) ForgotPasword(email, lang string) (resetToken string, err error) {
	userId, err := self.store.getUserId(email)
	if err != nil {
		return
	}

	user, err := self.store.getUser(userId)
	if err != nil {
		return
	}

	if user.confirmedAt.Equal(time.Time{}) {
		err = errors.New("The account has not been confirmed.")
		return
	}

	resetKey := uuid.NewV4().String()

	err = self.store.setUserResetKey(userId, resetKey, time.Now())
	if err != nil {
		return
	}

	return self.sendResetPaswordEmail(email, lang, resetKey)
}

func (self authImpl) ResetPassword(resetToken, newPassword string) error {
	email, _, tokenResetKey, err := self.parseResetToken(resetToken)
	if err != nil {
		return err
	}

	userId, err := self.store.getUserId(email)
	if err != nil {
		return err
	}

	user, err := self.store.getUser(userId)
	if err != nil {
		return err
	}

	if tokenResetKey != user.resetKey {
		return errors.New("The reset key is not valid.")
	}

	maxResetKeyAge, err := time.ParseDuration(self.cfg.MaxResetKeyAge)
	if err != nil {
		return err
	}

	if time.Now().After(user.resetKeyAt.Add(maxResetKeyAge)) {
		return errors.New("The reset key has expired.")
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return self.store.setUserHashedPass(userId, string(hashedPass))
}

func (self authImpl) Signout(sessionToken string) error {
	sessionId, err := self.parseSessionToken(sessionToken)
	if err != nil {
		return err
	}

	return self.store.removeSession(sessionId)
}

func (self authImpl) ChangePassword(sessionToken, oldPassword, newPassword string) error {
	sessionId, err := self.parseSessionToken(sessionToken)
	if err != nil {
		return err
	}

	session, err := self.store.getSession(sessionId)
	if err != nil {
		return err
	}

	user, err := self.store.getUser(session.userId)
	if err != nil {
		return err
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.hashedPass), []byte(oldPassword)); err != nil {
		return err
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return self.store.setUserHashedPass(session.userId, string(hashedPass))
}

func (self authImpl) ChangeEmail(sessionToken, password, newEmail string) error {
	sessionId, err := self.parseSessionToken(sessionToken)
	if err != nil {
		return err
	}

	session, err := self.store.getSession(sessionId)
	if err != nil {
		return err
	}

	user, err := self.store.getUser(session.userId)
	if err != nil {
		return err
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.hashedPass), []byte(password)); err != nil {
		return err
	}

	return self.store.setUserEmail(session.userId, newEmail)
}

func (self authImpl) GetUsers(adminKey string) ([]User, error) {
	if adminKey != self.cfg.AdminKey {
		return []User{}, errors.New("Unauthorized")
	}

	return self.store.getAllUsers()
}

func (self authImpl) CreateUser(adminKey, email, password, lang string) error {
	if adminKey != self.cfg.AdminKey {
		return errors.New("Unauthorized")
	}

	_, err := self.createUser(email, password, lang, true)
	return err
}

func (self authImpl) ChangeUserPassword(adminKey, userId, newPassword string) error {
	if adminKey != self.cfg.AdminKey {
		return errors.New("Unauthorized")
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return self.store.setUserHashedPass(userId, string(hashedPass))
}

func (self authImpl) ChangeUserEmail(adminKey, userId, newEmail string) error {
	if adminKey != self.cfg.AdminKey {
		return errors.New("Unauthorized")
	}

	return self.store.setUserEmail(userId, newEmail)
}

func (self authImpl) RemoveUser(adminKey, userId string) error {
	if adminKey != self.cfg.AdminKey {
		return errors.New("Unauthorized")
	}

	return self.store.removeUser(userId)
}

func (self authImpl) RemoveUnconfirmedUsers(adminKey string) error {
	if adminKey != self.cfg.AdminKey {
		return errors.New("Unauthorized")
	}

	maxUnconfirmedUsersAge, err := time.ParseDuration(self.cfg.MaxUnconfirmedUsersAge)
	if err != nil {
		return err
	}

	date := time.Now().Add(-1 * maxUnconfirmedUsersAge)
	return self.store.removeUnconfirmedUsersCreatedBefore(date)
}

func (self authImpl) createUser(email, password, lang string, isConfirmed bool) (confirmationKey string, err error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return
	}

	userId := uuid.NewV4().String()
	createdAt := time.Now()
	confirmationKey = uuid.NewV4().String()

	err = self.store.createUser(userId, createdAt, email, string(hashedPass), lang, confirmationKey)
	if err != nil {
		return
	}

	if isConfirmed {
		err = self.store.setUserConfirmedAt(userId, createdAt)
	}

	return
}

func (self authImpl) sendConfirmationEmail(email, lang, confirmationKey string) (confirmationToken string, err error) {
	confirmationToken, err = self.createConfirmationToken(email, lang, confirmationKey)
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

func (self authImpl) sendResetPaswordEmail(email, lang, resetKey string) (resetToken string, err error) {
	resetToken, err = self.createResetToken(email, lang, resetKey)
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

func (self authImpl) createConfirmationToken(email, lang, confirmationKey string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["email"] = email
	token.Claims["lang"] = lang
	token.Claims["confirmationKey"] = confirmationKey
	return token.SignedString([]byte(self.cfg.JwtKey))
}

func (self authImpl) parseConfirmationToken(confirmationToken string) (email, lang, confirmationKey string, err error) {
	token, err := jwt.Parse(confirmationToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(self.cfg.JwtKey), nil
	})
	if err != nil {
		return
	}
	if !token.Valid {
		return
	}

	email = token.Claims["email"].(string)
	lang = token.Claims["lang"].(string)
	confirmationKey = token.Claims["confirmationKey"].(string)
	return
}

func (self authImpl) createSessionToken(sessionId string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["sessionId"] = sessionId
	return token.SignedString([]byte(self.cfg.JwtKey))
}

func (self authImpl) parseSessionToken(sessionToken string) (sessionId string, err error) {
	token, err := jwt.Parse(sessionToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(self.cfg.JwtKey), nil
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

func (self authImpl) createResetToken(email, lang, resetKey string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["email"] = email
	token.Claims["lang"] = lang
	token.Claims["resetKey"] = resetKey
	return token.SignedString([]byte(self.cfg.JwtKey))
}

func (self authImpl) parseResetToken(resetToken string) (email, lang, resetKey string, err error) {
	token, err := jwt.Parse(resetToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(self.cfg.JwtKey), nil
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
