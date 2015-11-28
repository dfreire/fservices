package auth2

import (
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
	// ConfirmSignup(confirmationToken string) error
	// Signin(appId, email, password string) (sessionToken string, err error)
	// Signout(userId string) error
	// ForgotPasword(appId, email string) error
	// ResetPassword(resetToken, newPassword string) error
	// ChangePassword(userId, oldPassword, newPassword string) error
	// ChangeEmail(userId, password, newEmail string) error
	// GetAllUsers() ([]UserView, error)
	// GetUsersByAppId(appId string) ([]UserView, error)
	// CreateUser(appId, email, password string) error
	// ChangeUserPassword(userId, newPassword string) error
	// ChangeUserEmail(userId, newEmail string) error
	// RemoveUserById(userId string) error
}

type UserView struct {
	Id    string
	AppId string
	Email string
}

type AuthConfig struct {
	JwtKey            string
	FromEmail         string
	ConfirmationEmail ConfirmationEmailConfig
}

type ConfirmationEmailConfig map[string]struct {
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
	confirmationKey, err := self.createUser(appId, email, password, lang, true)
	if err != nil {
		return
	}

	return self.sendConfirmationEmail(appId, email, lang, confirmationKey)
}

func (self authImpl) ResendConfirmationMail(appId, email, lang string) (confirmationToken string, err error) {
	confirmationKey, err := self.store.getUserConfirmationKey(appId, email)
	if err != nil {
		return
	}

	return self.sendConfirmationEmail(appId, email, lang, confirmationKey)
}

func (self authImpl) createUser(appId, email, password, lang string, requireConfirmation bool) (confirmationKey string, err error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	if requireConfirmation {
		confirmationKey = uuid.NewV4().String()
	}

	err = self.store.createUser(uuid.NewV4().String(), appId, email, string(hashedPass), lang, confirmationKey, time.Now())
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

type confirmationToken struct {
	AppId           string
	Email           string
	Lang            string
	ConfirmationKey string
}

func (self authImpl) createConfirmationToken(appId, email, lang, confirmationKey string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["appId"] = appId
	token.Claims["email"] = email
	token.Claims["lang"] = lang
	token.Claims["confirmationKey"] = confirmationKey
	return token.SignedString([]byte(self.cfg.JwtKey))
}
