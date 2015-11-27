package auth2

import (
	"strings"
	"time"

	"github.com/dfreire/fservices/mailer"
	"github.com/dfreire/fservices/util"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type Auth interface {
	Signup(appId, email, password, lang string) error
	// ResendConfirmationMail(appId, email string) error
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

func (self authImpl) Signup(appId, email, password, lang string) error {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	confirmationKey := uuid.NewV4().String()

	if err := self.store.createUser(uuid.NewV4().String(), appId, email, string(hashedPass), lang, confirmationKey, time.Now()); err != nil {
		return err
	}

	confirmationToken, err := createConfirmationToken(appId, email, lang, confirmationKey)
	if err != nil {
		return err
	}

	templateValues := struct{ ConfirmationToken string }{confirmationToken}
	body, err := util.RenderTemplate(self.cfg.ConfirmationEmail[lang].Body, templateValues)
	if err != nil {
		return err
	}

	sendMailRequest := mailer.SendMailRequest{
		From:    self.cfg.FromEmail,
		To:      []string{email},
		Subject: self.cfg.ConfirmationEmail[lang].Subject,
		Body:    body,
	}

	if err := self.mailer.Send(sendMailRequest); err != nil {
		return err
	}

	return nil
}

func createConfirmationToken(appId, email, lang, confirmationKey string) (string, error) {
	confirmationToken := strings.Join([]string{appId, email, lang, confirmationKey}, "::")
	return confirmationToken, nil
}
