package auth2

import (
	"database/sql"
	"time"

	_ "github.com/lib/pq"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthPg struct {
	db *sql.DB
}

const SCHEMA = `
    DROP SCHEMA auth CASCADE;
    CREATE SCHEMA IF NOT EXISTS auth;

    CREATE TABLE IF NOT EXISTS auth.user (
       id                     CHAR(36) PRIMARY KEY NOT NULL,
       appId                  TEXT NOT NULL,
       email                  TEXT NOT NULL,
       hashedPass             TEXT NOT NULL,
       createdAt              TIMESTAMPTZ NOT NULL,
       confirmationToken      CHAR(36),
       sentConfirmationMailAt TIMESTAMPTZ,
       confirmedAt            TIMESTAMPTZ
    );

    CREATE UNIQUE INDEX IF NOT EXISTS auth_user_appId_email ON auth.user (appId, email);
`

func NewAuthPg(connectionString string) (AuthPg, error) {
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return AuthPg{}, err
	}

	if _, err = db.Exec(SCHEMA); err != nil {
		return AuthPg{}, err
	}

	return AuthPg{db}, nil
}

func (self AuthPg) Signup(appId, email, password string) (confirmationToken string, err error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return
	}

	insert := `INSERT INTO auth.user (id, appId, email, hashedPass, createdAt, confirmationToken)
        VALUES ($1, $2, $3, $4, $5, $6);`

	stmt, err := self.db.Prepare(insert)
	if err != nil {
		return
	}

	confirmationToken = uuid.NewV4().String()

	if _, err := stmt.Exec(uuid.NewV4().String(), appId, email, string(hashedPass), time.Now(), confirmationToken); err != nil {
		return "", err
	}

	return
}

func (self AuthPg) ConfirmSignup(confirmationToken string) error {
	return nil
}

func (self AuthPg) Signin(appId, email, password string) (sessionToken string, err error) {
	return "", nil
}
