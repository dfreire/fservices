package auth2

import (
	"database/sql"
	"time"

	"github.com/lib/pq"
)

type user struct {
	id                string
	createdAt         time.Time
	email             string
	hashedPass        string
	lang              string
	confirmationKey   string
	confirmationKeyAt time.Time
	resetKey          string
	resetKeyAt        time.Time
}

type session struct {
	id        string
	userId    string
	createdAt time.Time
}

type store interface {
	createSchema() error

	createUser(userId string, createdAt time.Time, email, hashedPass, lang, confirmationKey string) error
	setUserConfirmationKeyAt(userId string, confirmationKeyAt time.Time) error
	setUserResetKey(userId, resetKey string, resetKeyAt time.Time) error
	setUserHashedPass(userId, hashedPass string) error
	setUserEmail(userId, email string) error
	getUserId(email string) (userId string, err error)
	getUser(userId string) (user user, err error)

	createSession(sessionId, userId string, createdAt time.Time) error
	removeSession(sessionId string) error
	getSession(sessionId string) (session session, err error)
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
		   createdAt         TIMESTAMPTZ NOT NULL,
		   email             TEXT NOT NULL,
		   hashedPass        TEXT NOT NULL,
		   lang              auth.lang NOT NULL,
		   confirmationKey   CHAR(36) NOT NULL,
		   confirmationKeyAt TIMESTAMPTZ,
		   resetKey          CHAR(36),
		   resetKeyAt        TIMESTAMPTZ,

		   CONSTRAINT pk_auth_user PRIMARY KEY (id)
		);

		CREATE UNIQUE INDEX idx_auth_user_email ON auth.user (email);

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

func (self storePg) createUser(userId string, createdAt time.Time, email, hashedPass, lang, confirmationKey string) error {
	insert := `
		INSERT INTO auth.user
		(id, createdAt, email, hashedPass, lang, confirmationKey)
		VALUES
		($1, $2, $3, $4, $5, $6);
	`

	stmt, err := self.db.Prepare(insert)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(userId, createdAt, email, hashedPass, lang, confirmationKey)
	return err
}

func (self storePg) setUserConfirmationKeyAt(userId string, confirmationKeyAt time.Time) error {
	update := `
		UPDATE auth.user
		SET confirmationKeyAt = $1
		WHERE id = $2;
	`

	stmt, err := self.db.Prepare(update)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(confirmationKeyAt, userId)
	return err
}

func (self storePg) setUserResetKey(userId, resetKey string, resetKeyAt time.Time) error {
	update := `
		UPDATE auth.user
		SET resetKey = $1, resetKeyAt = $2
		WHERE id = $3;
	`

	stmt, err := self.db.Prepare(update)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(resetKey, resetKeyAt, userId)
	return err
}

func (self storePg) setUserHashedPass(userId, hashedPass string) error {
	update := `
		UPDATE auth.user
		SET hashedPass = $1, resetKey = NULL, resetKeyAt = NULL
		WHERE id = $2;
	`

	stmt, err := self.db.Prepare(update)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(hashedPass, userId)
	return err
}

func (self storePg) setUserEmail(userId, email string) error {
	update := `
		UPDATE auth.user
		SET email = $1
		WHERE id = $2;
	`

	stmt, err := self.db.Prepare(update)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(email, userId)
	return err
}

func (self storePg) getUserId(email string) (userId string, err error) {
	query := `
		SELECT id
		FROM auth.user
		WHERE email = $1;
	`
	err = self.db.QueryRow(query, email).Scan(&userId)
	return
}

func (self storePg) getUser(userId string) (user user, err error) {
	user.id = userId

	query := `
		SELECT createdAt, email, hashedPass, lang, confirmationKey, confirmationKeyAt, resetKey, resetKeyAt
		FROM auth.user
		WHERE id = $1;
	`

	var scanConfirmationKeyAt pq.NullTime
	var scanResetKey sql.NullString
	var scanResetKeyAt pq.NullTime

	err = self.db.QueryRow(query, userId).Scan(
		&user.createdAt,
		&user.email,
		&user.hashedPass,
		&user.lang,
		&user.confirmationKey,
		&scanConfirmationKeyAt,
		&scanResetKey,
		&scanResetKeyAt,
	)

	if scanConfirmationKeyAt.Valid {
		user.confirmationKeyAt = scanConfirmationKeyAt.Time
	}
	if scanResetKey.Valid {
		user.resetKey = scanResetKey.String
	}
	if scanResetKeyAt.Valid {
		user.resetKeyAt = scanResetKeyAt.Time
	}

	return
}

func (self storePg) createSession(sessionId, userId string, createdAt time.Time) error {
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

	_, err = stmt.Exec(sessionId, userId, createdAt)
	return err
}

func (self storePg) removeSession(sessionId string) error {
	delete := `
		DELETE FROM auth.session
		WHERE id = $1;
	`

	stmt, err := self.db.Prepare(delete)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(sessionId)
	return err
}

func (self storePg) getSession(sessionId string) (session session, err error) {
	session.id = sessionId
	query := `
		SELECT userId, createdAt
		FROM auth.session
		WHERE id = $1;
	`
	err = self.db.QueryRow(query, sessionId).Scan(&session.userId, &session.createdAt)
	return
}
