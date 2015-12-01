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
	createSession(id, userId string, createdAt time.Time) error
	removeSession(id string) error

	getUserConfirmation(appId, email string) (confirmationKey string, confirmedAt time.Time, err error)
	getUserPassword(appId, email string) (userId, hashedPass string, confirmedAt time.Time, err error)
	getSession(sessionId string) (userId string, createdAt time.Time, err error)
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
		   id                CHAR(36) NOT NULL,
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
		   sentResetTokenAt  TIMESTAMPTZ,

		   CONSTRAINT pk_auth_user PRIMARY KEY (id)
		);

		CREATE UNIQUE INDEX idx_auth_user_appId_email ON auth.user (appId, email);

		CREATE TABLE auth.session (
			id         CHAR(36) NOT NULL,
			userId     CHAR(36) NOT NULL,
			createdAt  TIMESTAMPTZ NOT NULL,

			CONSTRAINT pk_auth_session PRIMARY KEY (id),
			CONSTRAINT fk_auth_session_userId FOREIGN KEY (userId) REFERENCES auth.user(id)
		);
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
	update := `
		UPDATE auth.user
		SET confirmedAt = $1
		WHERE appId = $2 AND email = $3;
	`

	stmt, err := self.db.Prepare(update)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(confirmedAt, appId, email)
	return err
}

func (self storePg) createSession(id, userId string, createdAt time.Time) error {
	insert := `
		INSERT INTO auth.session
		(id, userId, createdAt)
		VALUES
		($1, $2, $3);
	`

	stmt, err := self.db.Prepare(insert)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(id, userId, createdAt)
	return err
}

func (self storePg) getUserConfirmation(appId, email string) (confirmationKey string, confirmedAt time.Time, err error) {
	query := `
		SELECT confirmationKey, confirmedAt
		FROM auth.user
		WHERE appId = $1 AND email = $2;
	`
	err = self.db.QueryRow(query, appId, email).Scan(&confirmationKey, &confirmedAt)
	return
}

func (self storePg) getUserPassword(appId, email string) (userId, hashedPass string, confirmedAt time.Time, err error) {
	query := `
		SELECT id, hashedPass, confirmedAt
		FROM auth.user
		WHERE appId = $1 AND email = $2;
	`
	err = self.db.QueryRow(query, appId, email).Scan(&userId, &hashedPass, &confirmedAt)
	return
}

func (self storePg) getSession(sessionId string) (userId string, createdAt time.Time, err error) {
	query := `
		SELECT userId, createdAt
		FROM auth.session
		WHERE id = $1;
	`
	err = self.db.QueryRow(query, sessionId).Scan(&userId, &createdAt)
	return
}

func (self storePg) removeSession(id string) error {
	delete := `
		DELETE FROM auth.session
		WHERE id = $1;
	`

	stmt, err := self.db.Prepare(delete)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(id)
	return err
}
