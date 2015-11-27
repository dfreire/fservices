package auth2

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/dfreire/fservices/mailer"
	"github.com/dfreire/fservices/util"
	"github.com/stretchr/testify/assert"
)

func TestSignup(t *testing.T) {
	auth, db := createAuthService()
	defer dropSchema(db)

	assert.Nil(t, auth.Signup("myapp", "dario.freire@gmail.com", "123", "en_US"))
}

func createAuthService() (Auth, *sql.DB) {
	var authConfig AuthConfig
	_, err := toml.DecodeFile("auth_test.toml", &authConfig)
	util.PanicIfNotNil(err)

	db, err := sql.Open("postgres", "postgres://drome:@localhost/fservices_test?sslmode=disable")
	util.PanicIfNotNil(err)
	storePg, err := NewStorePg(db)
	util.PanicIfNotNil(err)

	var smtpConfig mailer.SmtpConfig
	_, err = toml.DecodeFile(filepath.Join("..", "mailer", "mailer_test.secret.toml"), &smtpConfig)
	util.PanicIfNotNil(err)
	mailer := mailer.NewMailer(smtpConfig)

	return NewAuth(authConfig, storePg, mailer), db
}

func dropSchema(db *sql.DB) {
	_, err := db.Exec("DROP SCHEMA auth CASCADE;")
	util.PanicIfNotNil(err)
}
