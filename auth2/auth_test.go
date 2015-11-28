package auth2

import (
	"database/sql"
	"testing"

	"github.com/BurntSushi/toml"
	mailermock "github.com/dfreire/fservices/mailer/mock"
	"github.com/dfreire/fservices/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSignup(t *testing.T) {
	auth, mailerMock, db := createAuthService()
	defer dropSchema(db)

	mailerMock.On("Send", mock.AnythingOfType("mailer.Mail")).Return(nil)
	assert.Nil(t, auth.Signup("myapp", "dario.freire@gmail.com", "123", "en_US"))
	mailerMock.AssertNumberOfCalls(t, "Send", 1)
}

func createAuthService() (Auth, *mailermock.MailerMock, *sql.DB) {
	var authConfig AuthConfig
	_, err := toml.DecodeFile("auth_test.toml", &authConfig)
	util.PanicIfNotNil(err)

	db, err := sql.Open("postgres", "postgres://drome:@localhost/fservices_test?sslmode=disable")
	util.PanicIfNotNil(err)
	storePg, err := NewStorePg(db)
	util.PanicIfNotNil(err)

	mailer := new(mailermock.MailerMock)

	return NewAuth(authConfig, storePg, mailer), mailer, db
}

func dropSchema(db *sql.DB) {
	_, err := db.Exec("DROP SCHEMA auth CASCADE;")
	util.PanicIfNotNil(err)
}
