package auth

import (
	"errors"
	"time"

	"github.com/dfreire/fservices/mailer"
	"github.com/dfreire/fservices/util"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type Auth interface {
	Signup(email, password, lang string) (confirmationTokenStr string, err error)
	ResendConfirmationMail(email, lang string) (confirmationTokenStr string, err error)
	ConfirmSignup(confirmationTokenStr string) error
	Signin(email, password string) (sessionTokenStr string, err error)
	ForgotPasword(email, lang string) (resetTokenStr string, err error)
	ResetPassword(resetTokenStr, newPassword string) error

	ChangePassword(sessionTokenStr, oldPassword, newPassword string) error
	ChangeEmail(sessionTokenStr, password, newEmail string) error

	GetUsers(adminKey string) ([]User, error)
	CreateUser(adminKey, email, password, lang string) error
	ChangeUserPassword(adminKey, userId, newPassword string) error
	ChangeUserEmail(adminKey, userId, newEmail string) error
	RemoveUsers(adminKey string, userIds ...string) error

	RemoveUnconfirmedUsers(adminKey string) error
}

type AuthConfig struct {
	AdminKey               string
	JwtKey                 string
	MaxUnconfirmedUsersAge string
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

func (self authImpl) Signup(email, password, lang string) (confirmationTokenStr string, err error) {
	confirmationKey, err := self.createUser(email, password, lang, false)
	if err != nil {
		return
	}

	return self.sendConfirmationEmail(email, lang, confirmationKey)
}

func (self authImpl) ResendConfirmationMail(email, lang string) (confirmationTokenStr string, err error) {
	userId, err := self.store.getUserId(email)
	if err != nil {
		return
	}

	user, err := self.store.getPrivateUser(userId)
	if err != nil {
		return
	}

	return self.sendConfirmationEmail(email, lang, user.confirmationKey)
}

func (self authImpl) ConfirmSignup(confirmationTokenStr string) error {
	confirmationToken, err := parseConfirmationToken(self.cfg.JwtKey, confirmationTokenStr)
	if err != nil {
		return err
	}

	userId, err := self.store.getUserId(confirmationToken.email)
	if err != nil {
		return err
	}

	user, err := self.store.getPrivateUser(userId)
	if err != nil {
		return err
	}

	if confirmationToken.key != user.confirmationKey {
		return errors.New("The confirmation key is not valid.")
	}

	return self.store.setUserConfirmedAt(userId, time.Now())
}

func (self authImpl) Signin(email, password string) (sessionTokenStr string, err error) {
	userId, err := self.store.getUserId(email)
	if err != nil {
		return
	}

	user, err := self.store.getPrivateUser(userId)
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

	sessionTokenStr, err = privateSessionToken{sessionId, userId, sessionCreatedAt}.toString(self.cfg.JwtKey)
	return
}

func (self authImpl) ForgotPasword(email, lang string) (resetToken string, err error) {
	userId, err := self.store.getUserId(email)
	if err != nil {
		return
	}

	user, err := self.store.getPrivateUser(userId)
	if err != nil {
		return
	}

	if user.confirmedAt.Equal(time.Time{}) {
		err = errors.New("The account has not been confirmed.")
		return
	}

	resetKey := uuid.NewV4().String()

	err = self.store.setUserResetKey(userId, resetKey)
	if err != nil {
		return
	}

	return self.sendResetPaswordEmail(privateResetToken{email, lang, resetKey, time.Now()})
}

func (self authImpl) ResetPassword(resetTokenStr, newPassword string) error {
	resetToken, err := parseResetToken(self.cfg.JwtKey, resetTokenStr)
	if err != nil {
		return err
	}

	userId, err := self.store.getUserId(resetToken.email)
	if err != nil {
		return err
	}

	user, err := self.store.getPrivateUser(userId)
	if err != nil {
		return err
	}

	if resetToken.key != user.resetKey {
		return errors.New("The reset key is not valid.")
	}

	maxResetKeyAge, err := time.ParseDuration(self.cfg.MaxResetKeyAge)
	if err != nil {
		return err
	}

	if time.Now().After(resetToken.createdAt.Add(maxResetKeyAge)) {
		return errors.New("The reset key has expired.")
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return self.store.setUserHashedPass(userId, string(hashedPass))
}

func (self authImpl) ChangePassword(sessionTokenStr, oldPassword, newPassword string) error {
	sessionToken, err := parseSessionToken(self.cfg.JwtKey, sessionTokenStr)
	if err != nil {
		return err
	}

	user, err := self.store.getPrivateUser(sessionToken.userId)
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

	return self.store.setUserHashedPass(sessionToken.userId, string(hashedPass))
}

func (self authImpl) ChangeEmail(sessionTokenStr, password, newEmail string) error {
	sessionToken, err := parseSessionToken(self.cfg.JwtKey, sessionTokenStr)
	if err != nil {
		return err
	}

	user, err := self.store.getPrivateUser(sessionToken.userId)
	if err != nil {
		return err
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.hashedPass), []byte(password)); err != nil {
		return err
	}

	return self.store.setUserEmail(sessionToken.userId, newEmail)
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

func (self authImpl) RemoveUsers(adminKey string, userIds ...string) error {
	if adminKey != self.cfg.AdminKey {
		return errors.New("Unauthorized")
	}

	return self.store.removeUsers(userIds...)
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

func (self authImpl) sendConfirmationEmail(email, lang, confirmationKey string) (confirmationTokenStr string, err error) {
	confirmationToken := privateConfirmationToken{email, lang, confirmationKey}
	confirmationTokenStr, err = confirmationToken.toString(self.cfg.JwtKey)
	if err != nil {
		return
	}

	templateValues := struct{ ConfirmationTokenStr string }{confirmationTokenStr}
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

	return confirmationTokenStr, self.mailer.Send(mail)
}

func (self authImpl) sendResetPaswordEmail(resetKeyToken privateResetToken) (resetTokenStr string, err error) {
	resetTokenStr, err = resetKeyToken.toString(self.cfg.JwtKey)
	if err != nil {
		return
	}

	templateValues := struct{ ResetTokenStr string }{resetTokenStr}
	body, err := util.RenderTemplate(self.cfg.ResetPasswordEmail[resetKeyToken.lang].Body, templateValues)
	if err != nil {
		return
	}

	mail := mailer.Mail{
		From:    self.cfg.FromEmail,
		To:      []string{resetKeyToken.email},
		Subject: self.cfg.ResetPasswordEmail[resetKeyToken.lang].Subject,
		Body:    body,
	}

	return resetTokenStr, self.mailer.Send(mail)
}
