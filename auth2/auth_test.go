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
	auth, _, mailerMock, db := createAuthService()
	defer dropSchema(db)

	// request := mailer.SendMailRequest{
	// 	From:    cfg.FromEmail,
	// 	To:      []string{"dario.freire@gmail.com"},
	// 	Subject: cfg.ConfirmationEmail["en_US"].Subject,
	// 	Body:    util.MustRenderTemplate(cfg.ConfirmationEmail[lang].Body, templateValues)
	// }
	// mailerMock.On("Send", request).Return(nil)
	mailerMock.On("Send", mock.AnythingOfTypeArgument("mailer.SendMailRequest")).Return(nil)
	assert.Nil(t, auth.Signup("myapp", "dario.freire@gmail.com", "123", "en_US"))
	mailerMock.AssertNumberOfCalls(t, "Send", 1)
	mailerMock.AssertExpectations(t)
}

func createAuthService() (Auth, AuthConfig, *mailermock.MailerMock, *sql.DB) {
	var authConfig AuthConfig
	_, err := toml.DecodeFile("auth_test.toml", &authConfig)
	util.PanicIfNotNil(err)

	db, err := sql.Open("postgres", "postgres://drome:@localhost/fservices_test?sslmode=disable")
	util.PanicIfNotNil(err)
	storePg, err := NewStorePg(db)
	util.PanicIfNotNil(err)

	// var smtpConfig mailer.SmtpConfig
	// _, err = toml.DecodeFile(filepath.Join("..", "mailer", "mailer_test.secret.toml"), &smtpConfig)
	// util.PanicIfNotNil(err)
	// mailer := mailer.NewMailer(smtpConfig)
	mailer := new(mailermock.MailerMock)

	return NewAuth(authConfig, storePg, mailer), authConfig, mailer, db
}

func dropSchema(db *sql.DB) {
	_, err := db.Exec("DROP SCHEMA auth CASCADE;")
	util.PanicIfNotNil(err)
}
