package auth

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	mailermock "github.com/dfreire/fservices/mailer/mock"
	"github.com/dfreire/fservices/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var cfg AuthConfig

func TestMain(m *testing.M) {
	setup()
	retCode := m.Run()
	teardown()
	os.Exit(retCode)
}

func setup() {
	_, err := toml.DecodeFile("auth_test.toml", &cfg)
	util.PanicIfNotNil(err)
}

func teardown() {
}

func createAuthService() (Auth, store, *mailermock.MailerMock) {
	db, err := sql.Open("postgres", "postgres://drome:@localhost/fservices_test?sslmode=disable")
	util.PanicIfNotNil(err)

	_, err = db.Exec(`
		CREATE SCHEMA IF NOT EXISTS auth;
		DROP SCHEMA auth CASCADE;
	`)
	util.PanicIfNotNil(err)

	storePg := NewStorePg(db)
	util.PanicIfNotNil(storePg.createSchema())

	mailer := new(mailermock.MailerMock)

	return NewAuth(cfg, storePg, mailer), storePg, mailer
}

func TestSignup(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationTokenStr, err := auth.Signup("dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)
	assert.NotEmpty(t, confirmationTokenStr)

	confirmationToken, err := parseConfirmationToken(cfg.JwtKey, confirmationTokenStr)
	assert.Nil(t, err)

	userId, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)
	user, err := store.getPrivateUser(userId)
	assert.Nil(t, err)

	assert.Equal(t, "dario.freire@gmail.com", confirmationToken.email)
	assert.Equal(t, "en_US", confirmationToken.lang)
	assert.Equal(t, user.confirmationKey, confirmationToken.key)
	assert.NotEmpty(t, confirmationToken.key)
	assert.True(t, user.confirmedAt.Equal(time.Time{}))

	mailerMock.AssertNumberOfCalls(t, "Send", 1)
}

func TestResendConfirmationMail(t *testing.T) {
	auth, _, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken1, err := auth.Signup("dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	confirmationToken2, err := auth.ResendConfirmationMail("dario.freire@gmail.com", "en_US")
	assert.Nil(t, err)

	assert.Equal(t, confirmationToken1, confirmationToken2)
	mailerMock.AssertNumberOfCalls(t, "Send", 2)
}

func TestConfirmSignup(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	t0 := time.Now()

	confirmationToken, err := auth.Signup("dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	t1 := time.Now()

	userId, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)
	user, err := store.getPrivateUser(userId)
	assert.Nil(t, err)

	assert.True(t, user.confirmedAt.After(t0))
	assert.True(t, user.confirmedAt.Before(t1))
}

func TestSignin(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	t0 := time.Now()

	sessionTokenStr, err := auth.Signin("dario.freire@gmail.com", "123")
	assert.Nil(t, err)
	assert.NotEmpty(t, sessionTokenStr)

	t1 := time.Now()

	sessionToken, err := parseSessionToken(cfg.JwtKey, sessionTokenStr)
	assert.Nil(t, err)

	userId, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)

	assert.Equal(t, userId, sessionToken.userId)
	assert.True(t, sessionToken.createdAt.Unix() >= t0.Unix())
	assert.True(t, sessionToken.createdAt.Unix() <= t1.Unix())
}

func TestForgotPassword(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	t0 := time.Now()

	resetTokenStr, err := auth.ForgotPasword("dario.freire@gmail.com", "en_US")
	assert.Nil(t, err)

	t1 := time.Now()

	resetToken, err := parseResetToken(cfg.JwtKey, resetTokenStr)
	assert.Nil(t, err)

	userId, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)
	user, err := store.getPrivateUser(userId)
	assert.Nil(t, err)

	assert.Equal(t, "dario.freire@gmail.com", resetToken.email)
	assert.Equal(t, "en_US", resetToken.lang)
	assert.Equal(t, user.resetKey, resetToken.key)
	assert.NotEmpty(t, resetToken.key)
	assert.True(t, resetToken.createdAt.Unix() >= t0.Unix())
	assert.True(t, resetToken.createdAt.Unix() <= t1.Unix())

	mailerMock.AssertNumberOfCalls(t, "Send", 2)
}

func TestResetPassword(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	_, err = auth.Signin("dario.freire@gmail.com", "123")
	assert.Nil(t, err)

	resetToken, err := auth.ForgotPasword("dario.freire@gmail.com", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ResetPassword(resetToken, "abc"))

	userId, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)
	user, err := store.getPrivateUser(userId)
	assert.Nil(t, err)

	assert.Equal(t, "", user.resetKey)

	_, err = auth.Signin("dario.freire@gmail.com", "123")
	assert.NotNil(t, err)

	_, err = auth.Signin("dario.freire@gmail.com", "abc")
	assert.Nil(t, err)
}

func TestChangePassword(t *testing.T) {
	auth, _, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	sessionTokenStr, err := auth.Signin("dario.freire@gmail.com", "123")
	assert.Nil(t, err)

	err = auth.ChangePassword(sessionTokenStr, "123", "abc")
	assert.Nil(t, err)

	_, err = auth.Signin("dario.freire@gmail.com", "123")
	assert.NotNil(t, err)

	_, err = auth.Signin("dario.freire@gmail.com", "abc")
	assert.Nil(t, err)
}

func TestChangeEmail(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	sessionTokenStr, err := auth.Signin("dario.freire@gmail.com", "123")
	assert.Nil(t, err)

	err = auth.ChangeEmail(sessionTokenStr, "123", "dario.freire+changed@gmail.com")
	assert.Nil(t, err)

	_, err = store.getUserId("dario.freire@gmail.com")
	assert.NotNil(t, err)

	_, err = store.getUserId("dario.freire+changed@gmail.com")
	assert.Nil(t, err)
}

func TestGetUsers(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	t0 := time.Now()

	confirmationToken, err := auth.Signup("dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	_, err = auth.Signup("dario.freire+unconfirmed@gmail.com", "abc", "pt_PT")
	assert.Nil(t, err)

	t1 := time.Now()

	users, err := store.getAllUsers()
	assert.Nil(t, err)

	assert.NotEmpty(t, users[0].Id)
	assert.True(t, users[0].CreatedAt.After(t0))
	assert.True(t, users[0].CreatedAt.Before(t1))
	assert.Equal(t, "dario.freire@gmail.com", users[0].Email)
	assert.Equal(t, "en_US", users[0].Lang)
	assert.True(t, users[0].ConfirmedAt.After(t0))
	assert.True(t, users[0].ConfirmedAt.Before(t1))

	assert.NotEmpty(t, users[1].Id)
	assert.True(t, users[1].CreatedAt.After(t0))
	assert.True(t, users[1].CreatedAt.Before(t1))
	assert.Equal(t, "dario.freire+unconfirmed@gmail.com", users[1].Email)
	assert.Equal(t, "pt_PT", users[1].Lang)
	assert.True(t, users[1].ConfirmedAt.Equal(time.Time{}))
}

func TestCreateUser(t *testing.T) {
	auth, store, _ := createAuthService()

	t0 := time.Now()

	assert.Nil(t, auth.CreateUser(cfg.AdminKey, "dario.freire@gmail.com", "123", "en_US"))

	t1 := time.Now()

	userId, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)

	user, err := store.getPrivateUser(userId)
	assert.Nil(t, err)
	assert.NotEmpty(t, user.id)
	assert.True(t, user.createdAt.After(t0))
	assert.True(t, user.createdAt.Before(t1))
	assert.Equal(t, "dario.freire@gmail.com", user.email)
	assert.Equal(t, "en_US", user.lang)
	assert.True(t, user.confirmedAt.Equal(user.createdAt))

	sessionTokenStr, err := auth.Signin("dario.freire@gmail.com", "123")
	assert.Nil(t, err)
	assert.NotEmpty(t, sessionTokenStr)
}

func TestChangeUserPassword(t *testing.T) {
	auth, store, _ := createAuthService()

	assert.Nil(t, auth.CreateUser(cfg.AdminKey, "dario.freire@gmail.com", "123", "en_US"))

	userId, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)
	assert.NotEmpty(t, userId)

	_, err = auth.Signin("dario.freire@gmail.com", "123")
	assert.Nil(t, err)

	err = auth.ChangeUserPassword(cfg.AdminKey, userId, "abc")
	assert.Nil(t, err)

	_, err = auth.Signin("dario.freire@gmail.com", "123")
	assert.NotNil(t, err)

	_, err = auth.Signin("dario.freire@gmail.com", "abc")
	assert.Nil(t, err)
}

func TestChangeUserEmail(t *testing.T) {
	auth, store, _ := createAuthService()

	assert.Nil(t, auth.CreateUser(cfg.AdminKey, "dario.freire@gmail.com", "123", "en_US"))

	userId1, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)
	assert.NotEmpty(t, userId1)

	err = auth.ChangeUserEmail(cfg.AdminKey, userId1, "dario.freire+changed@gmail.com")
	assert.Nil(t, err)

	_, err = store.getUserId("dario.freire@gmail.com")
	assert.NotNil(t, err)

	userId2, err := store.getUserId("dario.freire+changed@gmail.com")
	assert.Nil(t, err)
	assert.Equal(t, userId1, userId2)
}

func TestRemoveUser(t *testing.T) {
	auth, store, _ := createAuthService()

	assert.Nil(t, auth.CreateUser(cfg.AdminKey, "dario.freire@gmail.com", "123", "en_US"))
	userId, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)
	assert.NotEmpty(t, userId)

	_, err = auth.Signin("dario.freire@gmail.com", "123")
	assert.Nil(t, err)

	assert.Nil(t, auth.RemoveUser(cfg.AdminKey, userId))

	_, err = auth.Signin("dario.freire@gmail.com", "123")
	assert.NotNil(t, err)

	_, err = store.getPrivateUser(userId)
	assert.NotNil(t, err)
}

func TestRemoveUnconfirmedUsers(t *testing.T) {
	auth, store, mailerMock := createAuthService()

	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	t0 := time.Now()

	_, err := auth.Signup("dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	t1 := time.Now()

	userId, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)

	user, err := store.getPrivateUser(userId)
	assert.Nil(t, err)
	assert.NotEmpty(t, user.id)
	assert.True(t, user.createdAt.After(t0))
	assert.True(t, user.createdAt.Before(t1))
	assert.Equal(t, "dario.freire@gmail.com", user.email)
	assert.Equal(t, "en_US", user.lang)
	assert.True(t, user.confirmedAt.Equal(time.Time{}))

	time.Sleep(2 * time.Nanosecond)

	err = auth.RemoveUnconfirmedUsers(cfg.AdminKey)
	assert.Nil(t, err)

	_, err = store.getPrivateUser(userId)
	assert.NotNil(t, err)
}
