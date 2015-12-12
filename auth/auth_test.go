package auth2

import (
	"database/sql"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	mailermock "github.com/dfreire/fservices/mailer/mock"
	"github.com/dfreire/fservices/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func createAuthService() (Auth, store, *mailermock.MailerMock) {
	var authConfig AuthConfig
	_, err := toml.DecodeFile("auth_test.toml", &authConfig)
	util.PanicIfNotNil(err)

	db, err := sql.Open("postgres", "postgres://drome:@localhost/fservices_test?sslmode=disable")
	util.PanicIfNotNil(err)
	storePg := NewStorePg(db)

	_, err = db.Exec(`
		CREATE SCHEMA IF NOT EXISTS auth;
		DROP SCHEMA auth CASCADE;
	`)
	util.PanicIfNotNil(err)
	util.PanicIfNotNil(storePg.createSchema())

	mailer := new(mailermock.MailerMock)

	return NewAuth(authConfig, storePg, mailer), storePg, mailer
}

func TestSignup(t *testing.T) {
	auth, store, mailerMock := createAuthService()

	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("myapp", "dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)
	assert.NotEmpty(t, confirmationToken)

	appId, email, lang, confirmationKey, err := auth.(authImpl).parseConfirmationToken(confirmationToken)
	assert.Nil(t, err)

	userId, err := store.getUserId("myapp", "dario.freire@gmail.com")
	assert.Nil(t, err)
	user, err := store.getUser(userId)
	assert.Nil(t, err)

	assert.Equal(t, "myapp", appId)
	assert.Equal(t, "dario.freire@gmail.com", email)
	assert.Equal(t, "en_US", lang)
	assert.Equal(t, confirmationKey, user.confirmationKey)
	assert.NotEmpty(t, confirmationKey)
	assert.True(t, user.confirmationKeyAt.Equal(time.Time{}))

	mailerMock.AssertNumberOfCalls(t, "Send", 1)
}

func TestResendConfirmationMail(t *testing.T) {
	auth, _, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken1, err := auth.Signup("myapp", "dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	confirmationToken2, err := auth.ResendConfirmationMail("myapp", "dario.freire@gmail.com", "en_US")
	assert.Nil(t, err)

	assert.Equal(t, confirmationToken1, confirmationToken2)
	mailerMock.AssertNumberOfCalls(t, "Send", 2)
}

func TestConfirmSignup(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	t0 := time.Now()

	confirmationToken, err := auth.Signup("myapp", "dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	t1 := time.Now()

	userId, err := store.getUserId("myapp", "dario.freire@gmail.com")
	assert.Nil(t, err)
	user, err := store.getUser(userId)
	assert.Nil(t, err)

	assert.True(t, user.confirmationKeyAt.After(t0))
	assert.True(t, user.confirmationKeyAt.Before(t1))
}

func TestSignin(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("myapp", "dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	t0 := time.Now()

	sessionToken, err := auth.Signin("myapp", "dario.freire@gmail.com", "123")
	assert.Nil(t, err)
	assert.NotEmpty(t, sessionToken)

	t1 := time.Now()

	sessionId, err := auth.(authImpl).parseSessionToken(sessionToken)
	assert.Nil(t, err)
	session, err := store.getSession(sessionId)
	assert.Nil(t, err)

	userId, err := store.getUserId("myapp", "dario.freire@gmail.com")
	assert.Nil(t, err)

	assert.Equal(t, userId, session.userId)
	assert.True(t, session.createdAt.After(t0))
	assert.True(t, session.createdAt.Before(t1))
}

func TestForgotPassword(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("myapp", "dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	t0 := time.Now()

	resetToken, err := auth.ForgotPasword("myapp", "dario.freire@gmail.com", "en_US")
	assert.Nil(t, err)

	t1 := time.Now()

	appId, email, lang, resetKey, err := auth.(authImpl).parseResetToken(resetToken)
	assert.Nil(t, err)

	userId, err := store.getUserId("myapp", "dario.freire@gmail.com")
	assert.Nil(t, err)
	user, err := store.getUser(userId)
	assert.Nil(t, err)

	assert.Equal(t, "myapp", appId)
	assert.Equal(t, "dario.freire@gmail.com", email)
	assert.Equal(t, "en_US", lang)
	assert.Equal(t, resetKey, user.resetKey)
	assert.NotEmpty(t, resetKey)
	assert.True(t, user.resetKeyAt.After(t0))
	assert.True(t, user.resetKeyAt.Before(t1))

	mailerMock.AssertNumberOfCalls(t, "Send", 2)
}

func TestResetPassword(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("myapp", "dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	_, err = auth.Signin("myapp", "dario.freire@gmail.com", "123")
	assert.Nil(t, err)

	resetToken, err := auth.ForgotPasword("myapp", "dario.freire@gmail.com", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ResetPassword(resetToken, "abc"))

	userId, err := store.getUserId("myapp", "dario.freire@gmail.com")
	assert.Nil(t, err)
	user, err := store.getUser(userId)
	assert.Nil(t, err)

	assert.Equal(t, "", user.resetKey)
	assert.True(t, user.resetKeyAt.Equal(time.Time{}))

	_, err = auth.Signin("myapp", "dario.freire@gmail.com", "123")
	assert.NotNil(t, err)

	_, err = auth.Signin("myapp", "dario.freire@gmail.com", "abc")
	assert.Nil(t, err)
}

func TestSignout(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("myapp", "dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	sessionToken, err := auth.Signin("myapp", "dario.freire@gmail.com", "123")
	assert.Nil(t, err)

	sessionId, err := auth.(authImpl).parseSessionToken(sessionToken)
	assert.Nil(t, err)

	_, err = store.getSession(sessionId)
	assert.Nil(t, err)

	assert.Nil(t, auth.Signout(sessionToken))

	_, err = store.getSession(sessionId)
	assert.NotNil(t, err)
}

func TestChangePassword(t *testing.T) {
	auth, _, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("myapp", "dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	sessionToken, err := auth.Signin("myapp", "dario.freire@gmail.com", "123")
	assert.Nil(t, err)

	err = auth.ChangePassword(sessionToken, "123", "abc")
	assert.Nil(t, err)

	_, err = auth.Signin("myapp", "dario.freire@gmail.com", "123")
	assert.NotNil(t, err)

	_, err = auth.Signin("myapp", "dario.freire@gmail.com", "abc")
	assert.Nil(t, err)
}

func TestChangeEmail(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("myapp", "dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	sessionToken, err := auth.Signin("myapp", "dario.freire@gmail.com", "123")
	assert.Nil(t, err)

	err = auth.ChangeEmail(sessionToken, "123", "dario.freire+changed@gmail.com")
	assert.Nil(t, err)

	_, err = store.getUserId("myapp", "dario.freire@gmail.com")
	assert.NotNil(t, err)

	_, err = store.getUserId("myapp", "dario.freire+changed@gmail.com")
	assert.Nil(t, err)
}
