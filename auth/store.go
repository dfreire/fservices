package auth2

import (
	"database/sql"
	"time"

	_ "github.com/lib/pq"
)

type store interface {
	createSchema() error
	createUser(id, appId, email, hashedPass, lang, confirmationKey string, createdAt, confirmedAt time.Time) error
	setUserConfirmedAt(appId, email string, confirmedAt time.Time) error

	getUserConfirmation(appId, email string) (confirmationKey string, confirmedAt time.Time, err error)
}

type storePg struct {
	db *sql.DB
}

func NewStorePg(db *sql.DB) storePg {
	return storePg{db}
}

func (self storePg) createSchema() error {
	schema := `
		CREATE SCHEMA auth;

		CREATE TYPE auth.lang AS ENUM ('pt_PT', 'en_US');

		CREATE TABLE auth.user (
		   id                CHAR(36) PRIMARY KEY NOT NULL,
		   appId             TEXT NOT NULL,
		   email             TEXT NOT NULL,
		   hashedPass        TEXT NOT NULL,
		   createdAt         TIMESTAMPTZ NOT NULL,
		   lang              auth.lang NOT NULL,
		   -- confirm
		   confirmationKey   CHAR(36),
		   confirmedAt       TIMESTAMPTZ,
		   -- reset
		   resetToken        CHAR(36),
		   sentResetTokenAt  TIMESTAMPTZ
		);

		CREATE UNIQUE INDEX auth_user_appId_email ON auth.user (appId, email);
	`

	_, err := self.db.Exec(schema)
	return err
}

func (self storePg) createUser(id, appId, email, hashedPass, lang, confirmationKey string, createdAt, confirmedAt time.Time) error {
	insert := `
		INSERT INTO auth.user
		(id, appId, email, hashedPass, lang, confirmationKey, createdAt, confirmedAt)
		VALUES
		($1, $2, $3, $4, $5, $6, $7, $8);
	`

	stmt, err := self.db.Prepare(insert)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(id, appId, email, hashedPass, lang, confirmationKey, createdAt, confirmedAt)
	return err
}

func (self storePg) setUserConfirmedAt(appId, email string, confirmedAt time.Time) error {
	insert := `
		UPDATE auth.user
		SET confirmedAt = $1
		WHERE appId = $2 AND email = $3;
	`

	stmt, err := self.db.Prepare(insert)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(confirmedAt, appId, email)
	return err
}

func (self storePg) getUserConfirmation(appId, email string) (confirmationKey string, confirmedAt time.Time, err error) {
	query := `
		SELECT confirmationKey, confirmedAt
		FROM auth.user
		WHERE appId = $1 AND email = $2;
	`
	self.db.QueryRow(query, appId, email).Scan(&confirmationKey, &confirmedAt)
	return
}
