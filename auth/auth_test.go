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

	confirmationToken, err := auth.Signup("dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)
	assert.NotEmpty(t, confirmationToken)

	email, lang, confirmationKey, err := auth.(authImpl).parseConfirmationToken(confirmationToken)
	assert.Nil(t, err)

	userId, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)
	user, err := store.getUser(userId)
	assert.Nil(t, err)

	assert.Equal(t, "dario.freire@gmail.com", email)
	assert.Equal(t, "en_US", lang)
	assert.Equal(t, confirmationKey, user.confirmationKey)
	assert.NotEmpty(t, confirmationKey)
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
	user, err := store.getUser(userId)
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

	sessionToken, err := auth.Signin("dario.freire@gmail.com", "123")
	assert.Nil(t, err)
	assert.NotEmpty(t, sessionToken)

	t1 := time.Now()

	sessionId, err := auth.(authImpl).parseSessionToken(sessionToken)
	assert.Nil(t, err)
	session, err := store.getSession(sessionId)
	assert.Nil(t, err)

	userId, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)

	assert.Equal(t, userId, session.userId)
	assert.True(t, session.createdAt.After(t0))
	assert.True(t, session.createdAt.Before(t1))
}

func TestForgotPassword(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	t0 := time.Now()

	resetToken, err := auth.ForgotPasword("dario.freire@gmail.com", "en_US")
	assert.Nil(t, err)

	t1 := time.Now()

	email, lang, resetKey, err := auth.(authImpl).parseResetToken(resetToken)
	assert.Nil(t, err)

	userId, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)
	user, err := store.getUser(userId)
	assert.Nil(t, err)

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
	user, err := store.getUser(userId)
	assert.Nil(t, err)

	assert.Equal(t, "", user.resetKey)
	assert.True(t, user.resetKeyAt.Equal(time.Time{}))

	_, err = auth.Signin("dario.freire@gmail.com", "123")
	assert.NotNil(t, err)

	_, err = auth.Signin("dario.freire@gmail.com", "abc")
	assert.Nil(t, err)
}

func TestSignout(t *testing.T) {
	auth, store, mailerMock := createAuthService()
	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)

	confirmationToken, err := auth.Signup("dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	sessionToken, err := auth.Signin("dario.freire@gmail.com", "123")
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

	confirmationToken, err := auth.Signup("dario.freire@gmail.com", "123", "en_US")
	assert.Nil(t, err)

	assert.Nil(t, auth.ConfirmSignup(confirmationToken))

	sessionToken, err := auth.Signin("dario.freire@gmail.com", "123")
	assert.Nil(t, err)

	err = auth.ChangePassword(sessionToken, "123", "abc")
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

	sessionToken, err := auth.Signin("dario.freire@gmail.com", "123")
	assert.Nil(t, err)

	err = auth.ChangeEmail(sessionToken, "123", "dario.freire+changed@gmail.com")
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
	adminKey := "ba5a5c16-840a-4a01-8817-3799d0492551"

	t0 := time.Now()

	assert.Nil(t, auth.CreateUser(adminKey, "dario.freire@gmail.com", "123", "en_US"))

	t1 := time.Now()

	userId, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)

	user, err := store.getUser(userId)
	assert.Nil(t, err)
	assert.NotEmpty(t, user.id)
	assert.True(t, user.createdAt.After(t0))
	assert.True(t, user.createdAt.Before(t1))
	assert.Equal(t, "dario.freire@gmail.com", user.email)
	assert.Equal(t, "en_US", user.lang)
	assert.True(t, user.confirmedAt.Equal(user.createdAt))

	sessionToken, err := auth.Signin("dario.freire@gmail.com", "123")
	assert.Nil(t, err)
	assert.NotEmpty(t, sessionToken)
}

func TestChangeUserPassword(t *testing.T) {
	auth, store, _ := createAuthService()
	adminKey := "ba5a5c16-840a-4a01-8817-3799d0492551"

	assert.Nil(t, auth.CreateUser(adminKey, "dario.freire@gmail.com", "123", "en_US"))

	userId, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)
	assert.NotEmpty(t, userId)

	_, err = auth.Signin("dario.freire@gmail.com", "123")
	assert.Nil(t, err)

	err = auth.ChangeUserPassword(adminKey, userId, "abc")
	assert.Nil(t, err)

	_, err = auth.Signin("dario.freire@gmail.com", "123")
	assert.NotNil(t, err)

	_, err = auth.Signin("dario.freire@gmail.com", "abc")
	assert.Nil(t, err)
}

func TestChangeUserEmail(t *testing.T) {
	auth, store, _ := createAuthService()
	adminKey := "ba5a5c16-840a-4a01-8817-3799d0492551"

	assert.Nil(t, auth.CreateUser(adminKey, "dario.freire@gmail.com", "123", "en_US"))

	userId1, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)
	assert.NotEmpty(t, userId1)

	err = auth.ChangeUserEmail(adminKey, userId1, "dario.freire+changed@gmail.com")
	assert.Nil(t, err)

	_, err = store.getUserId("dario.freire@gmail.com")
	assert.NotNil(t, err)

	userId2, err := store.getUserId("dario.freire+changed@gmail.com")
	assert.Nil(t, err)
	assert.Equal(t, userId1, userId2)
}

func TestRemoveUser(t *testing.T) {
	auth, store, _ := createAuthService()
	adminKey := "ba5a5c16-840a-4a01-8817-3799d0492551"

	assert.Nil(t, auth.CreateUser(adminKey, "dario.freire@gmail.com", "123", "en_US"))
	userId, err := store.getUserId("dario.freire@gmail.com")
	assert.Nil(t, err)
	assert.NotEmpty(t, userId)

	sessionToken1, err := auth.Signin("dario.freire@gmail.com", "123")
	assert.Nil(t, err)

	sessionId1, err := auth.(authImpl).parseSessionToken(sessionToken1)
	assert.Nil(t, err)

	_, err = store.getSession(sessionId1)
	assert.Nil(t, err)

	sessionToken2, err := auth.Signin("dario.freire@gmail.com", "123")
	assert.Nil(t, err)

	sessionId2, err := auth.(authImpl).parseSessionToken(sessionToken2)
	assert.Nil(t, err)

	_, err = store.getSession(sessionId2)
	assert.Nil(t, err)

	assert.NotEqual(t, sessionId1, sessionId2)

	assert.Nil(t, auth.RemoveUser(adminKey, userId))

	_, err = store.getUser(userId)
	assert.NotNil(t, err)

	_, err = store.getSession(sessionId1)
	assert.NotNil(t, err)

	_, err = store.getSession(sessionId2)
	assert.NotNil(t, err)
}
