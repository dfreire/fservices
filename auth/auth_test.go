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
	mailerMock.AssertNumberOfCalls(t, "Send", 1)

	confirmationKey, confirmedAt, err := store.getUserConfirmation("myapp", "dario.freire@gmail.com")
	assert.Nil(t, err)

	assert.NotEmpty(t, confirmationKey)
	assert.True(t, time.Time{}.Equal(confirmedAt))
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

func createAuthService() (Auth, store, *mailermock.MailerMock) {
	var authConfig AuthConfig
	_, err := toml.DecodeFile("auth_test.toml", &authConfig)
	util.PanicIfNotNil(err)

	db, err := sql.Open("postgres", "postgres://drome:@localhost/fservices_test?sslmode=disable")
	util.PanicIfNotNil(err)
	storePg := NewStorePg(db)

	_, err = db.Exec("DROP SCHEMA auth CASCADE;")
	util.PanicIfNotNil(err)
	util.PanicIfNotNil(storePg.createSchema())

	mailer := new(mailermock.MailerMock)

	return NewAuth(authConfig, storePg, mailer), storePg, mailer
}
