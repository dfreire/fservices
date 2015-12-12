package auth2

import (
	"database/sql"
	"time"

	"github.com/lib/pq"
)

type user struct {
	id                string
	createdAt         time.Time
	appId             string
	email             string
	hashedPass        string
	lang              string
	confirmationKey   string
	confirmationKeyAt time.Time
	resetKey          string
	resetKeyAt        time.Time
}

type store interface {
	createSchema() error

	createUser(userId string, createdAt time.Time, appId, email, hashedPass, lang, confirmationKey string) error
	setUserConfirmationKeyAt(appId, email string, confirmationKeyAt time.Time) error
	setUserResetKey(appId, email, resetKey string, resetKeyAt time.Time) error
	setUserHashedPass(appId, email, hashedPass string) error

	getUserId(appId, email string) (userId string, err error)
	getUser(userId string) (user user, err error)

	getUserConfirmation(appId, email string) (confirmationKey string, confirmationKeyAt time.Time, err error)
	getUserPassword(appId, email string) (userId, hashedPass string, confirmationKeyAt time.Time, err error)
	// getUserResetKey(appId, email string) (resetKey string, resetKeyAt time.Time, err error)

	createSession(id, userId string, createdAt time.Time) error
	removeSession(id string) error
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
		   createdAt         TIMESTAMPTZ NOT NULL,
		   appId             TEXT NOT NULL,
		   email             TEXT NOT NULL,
		   hashedPass        TEXT NOT NULL,
		   lang              auth.lang NOT NULL,
		   confirmationKey   CHAR(36) NOT NULL,
		   confirmationKeyAt TIMESTAMPTZ,
		   resetKey          CHAR(36),
		   resetKeyAt        TIMESTAMPTZ,

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

func (self storePg) createUser(userId string, createdAt time.Time, appId, email, hashedPass, lang, confirmationKey string) error {
	insert := `
		INSERT INTO auth.user
		(id, createdAt, appId, email, hashedPass, lang, confirmationKey)
		VALUES
		($1, $2, $3, $4, $5, $6, $7);
	`

	stmt, err := self.db.Prepare(insert)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(userId, createdAt, appId, email, hashedPass, lang, confirmationKey)
	return err
}

func (self storePg) setUserConfirmationKeyAt(appId, email string, confirmationKeyAt time.Time) error {
	update := `
		UPDATE auth.user
		SET confirmationKeyAt = $1
		WHERE appId = $2 AND email = $3;
	`

	stmt, err := self.db.Prepare(update)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(confirmationKeyAt, appId, email)
	return err
}

func (self storePg) setUserResetKey(appId, email, resetKey string, resetKeyAt time.Time) error {
	update := `
		UPDATE auth.user
		SET resetKey = $1, resetKeyAt = $2
		WHERE appId = $3 AND email = $4;
	`

	stmt, err := self.db.Prepare(update)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(resetKey, resetKeyAt, appId, email)
	return err
}

func (self storePg) setUserHashedPass(appId, email, hashedPass string) error {
	update := `
		UPDATE auth.user
		SET hashedPass = $1, resetKey = NULL, resetKeyAt = NULL
		WHERE appId = $2 AND email = $3;
	`

	stmt, err := self.db.Prepare(update)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(hashedPass, appId, email)
	return err
}

func (self storePg) getUserId(appId, email string) (userId string, err error) {
	query := `
		SELECT id
		FROM auth.user
		WHERE appId = $1 AND email = $2;
	`
	err = self.db.QueryRow(query, appId, email).Scan(&userId)
	return
}

func (self storePg) getUser(userId string) (user user, err error) {
	query := `
		SELECT createdAt, appId, email, hashedPass, lang, confirmationKey, confirmationKeyAt, resetKey, resetKeyAt
		FROM auth.user
		WHERE id = $1;
	`

	var scanConfirmationKeyAt pq.NullTime
	var scanResetKey sql.NullString
	var scanResetKeyAt pq.NullTime

	err = self.db.QueryRow(query, userId).Scan(
		&user.createdAt,
		&user.appId,
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

func (self storePg) getUserConfirmation(appId, email string) (confirmationKey string, confirmationKeyAt time.Time, err error) {
	var scanConfirmationKeyAt pq.NullTime
	query := `
		SELECT confirmationKey, confirmationKeyAt
		FROM auth.user
		WHERE appId = $1 AND email = $2;
	`
	err = self.db.QueryRow(query, appId, email).Scan(&confirmationKey, &scanConfirmationKeyAt)
	if scanConfirmationKeyAt.Valid {
		confirmationKeyAt = scanConfirmationKeyAt.Time
	}
	return
}

func (self storePg) getUserPassword(appId, email string) (userId, hashedPass string, confirmationKeyAt time.Time, err error) {
	query := `
		SELECT id, hashedPass, confirmationKeyAt
		FROM auth.user
		WHERE appId = $1 AND email = $2;
	`
	err = self.db.QueryRow(query, appId, email).Scan(&userId, &hashedPass, &confirmationKeyAt)
	return
}

func (self storePg) getUserResetKey(appId, email string) (resetKey string, resetKeyAt time.Time, err error) {
	var scanResetKey sql.NullString
	var scanSetResetKeyAt pq.NullTime
	query := `
		SELECT resetKey, resetKeyAt
		FROM auth.user
		WHERE appId = $1 AND email = $2;
	`
	err = self.db.QueryRow(query, appId, email).Scan(&scanResetKey, &scanSetResetKeyAt)
	if scanResetKey.Valid {
		resetKey = scanResetKey.String
	}
	if scanSetResetKeyAt.Valid {
		resetKeyAt = scanSetResetKeyAt.Time
	}
	return
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

func (self storePg) getSession(sessionId string) (userId string, createdAt time.Time, err error) {
	query := `
		SELECT userId, createdAt
		FROM auth.session
		WHERE id = $1;
	`
	err = self.db.QueryRow(query, sessionId).Scan(&userId, &createdAt)
	return
}
