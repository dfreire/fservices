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

func TestSignup(t *testing.T) {
	auth, store, mailerMock := createAuthService()

	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("myapp", "dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)
	assert.NotEmpty(t, confirmationToken)

	appId, email, lang, confirmationKey1, err := auth.(authImpl).parseConfirmationToken(confirmationToken)
	assert.Nil(t, err)

	confirmationKey2, confirmedAt, err := store.getUserConfirmation("myapp", "dario.freire@gmail.com")
	assert.Nil(t, err)

	assert.Equal(t, "myapp", appId)
	assert.Equal(t, "dario.freire@gmail.com", email)
	assert.Equal(t, "en_US", lang)
	assert.Equal(t, confirmationKey1, confirmationKey2)
	assert.NotEmpty(t, confirmationKey1)
	assert.True(t, confirmedAt.Equal(time.Time{}))

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

	_, confirmedAt, err := store.getUserConfirmation("myapp", "dario.freire@gmail.com")
	assert.Nil(t, err)

	assert.True(t, confirmedAt.After(t0))
	assert.True(t, confirmedAt.Before(t1))
}

func TestSignin(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("myapp", "dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	sessionToken, err := auth.Signin("myapp", "dario.freire@gmail.com", "123")
	assert.Nil(t, err)
	assert.NotEmpty(t, sessionToken)

	sessionId, userId1, createdAt1, err := auth.(authImpl).parseSessionToken(sessionToken)
	assert.Nil(t, err)
	userId2, createdAt2, err := store.getSession(sessionId)
	assert.Nil(t, err)

	assert.Equal(t, userId1, userId2)
	assert.True(t, createdAt1.Equal(createdAt2))
}

func TestSignout(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("myapp", "dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	sessionToken, err := auth.Signin("myapp", "dario.freire@gmail.com", "123")
	assert.Nil(t, err)

	sessionId, _, _, err := auth.(authImpl).parseSessionToken(sessionToken)
	assert.Nil(t, err)

	_, _, err = store.getSession(sessionId)
	assert.Nil(t, err)

	assert.Nil(t, auth.Signout(sessionToken))

	_, _, err = store.getSession(sessionId)
	assert.NotNil(t, err)
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

	appId, email, lang, resetKey1, err := auth.(authImpl).parseResetToken(resetToken)
	assert.Nil(t, err)

	resetKey2, setResetKeyAt, err := store.getUserResetKey(appId, email)
	assert.Nil(t, err)

	assert.Equal(t, "myapp", appId)
	assert.Equal(t, "dario.freire@gmail.com", email)
	assert.Equal(t, "en_US", lang)
	assert.Equal(t, resetKey1, resetKey2)
	assert.NotEmpty(t, resetKey1)
	assert.True(t, setResetKeyAt.After(t0))
	assert.True(t, setResetKeyAt.Before(t1))

	mailerMock.AssertNumberOfCalls(t, "Send", 2)
}

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
