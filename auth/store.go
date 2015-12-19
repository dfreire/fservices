package auth2

import (
	"database/sql"
	"time"

	"github.com/lib/pq"
)

type user struct {
	id              string
	createdAt       time.Time
	email           string
	hashedPass      string
	lang            string
	confirmationKey string
	confirmedAt     time.Time
	resetKey        string
	resetKeyAt      time.Time
}

type User struct {
	Id          string
	CreatedAt   time.Time
	Email       string
	Lang        string
	ConfirmedAt time.Time
}

type session struct {
	id         string
	userId     string
	activityAt time.Time
}

type store interface {
	createSchema() error

	createUser(userId string, createdAt time.Time, email, hashedPass, lang, confirmationKey string) error
	removeUser(userId string) error
	setUserConfirmedAt(userId string, confirmedAt time.Time) error
	setUserResetKey(userId, resetKey string, resetKeyAt time.Time) error
	setUserHashedPass(userId, hashedPass string) error
	setUserEmail(userId, email string) error
	getUserId(email string) (userId string, err error)
	getUser(userId string) (user user, err error)
	getAllUsers() (users []User, err error)

	createSession(sessionId, userId string, activityAt time.Time) error
	removeSession(sessionId string) error
	getSession(sessionId string) (session session, err error)

	removeUnconfirmedUsersCreatedBefore(date time.Time) error
	removeSessionsIdleBefore(date time.Time) error
	// removeResetKeysIssuedBefore(date time.Time) error
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
		   id              CHAR(36) NOT NULL,
		   createdAt       TIMESTAMPTZ NOT NULL,
		   email           TEXT NOT NULL,
		   hashedPass      TEXT NOT NULL,
		   lang            auth.lang NOT NULL,
		   confirmationKey CHAR(36) NOT NULL,
		   confirmedAt     TIMESTAMPTZ,
		   resetKey        CHAR(36),
		   resetKeyAt      TIMESTAMPTZ,

		   CONSTRAINT pk_auth_user PRIMARY KEY (id)
		);

		CREATE UNIQUE INDEX idx_auth_user_email ON auth.user (email);

		CREATE TABLE auth.session (
			id         CHAR(36) NOT NULL,
			userId     CHAR(36) NOT NULL,
			activityAt TIMESTAMPTZ NOT NULL,

			CONSTRAINT pk_auth_session PRIMARY KEY (id),
			CONSTRAINT fk_auth_session_userId FOREIGN KEY (userId) REFERENCES auth.user(id)
		);

		CREATE INDEX idx_auth_session_userId ON auth.session (userId);
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

func (self storePg) removeUser(userId string) error {
	tx, err := self.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmtSession, err := tx.Prepare("DELETE FROM auth.session WHERE userId = $1;")
	if err != nil {
		return err
	}

	_, err = stmtSession.Exec(userId)
	if err != nil {
		return err
	}

	stmtUser, err := tx.Prepare("DELETE FROM auth.user WHERE id = $1;")
	if err != nil {
		return err
	}

	_, err = stmtUser.Exec(userId)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (self storePg) setUserConfirmedAt(userId string, confirmedAt time.Time) error {
	update := `
		UPDATE auth.user
		SET confirmedAt = $1
		WHERE id = $2;
	`

	stmt, err := self.db.Prepare(update)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(confirmedAt, userId)
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
		SELECT createdAt, email, hashedPass, lang, confirmationKey, confirmedAt, resetKey, resetKeyAt
		FROM auth.user
		WHERE id = $1;
	`

	var scanConfirmedAt pq.NullTime
	var scanResetKey sql.NullString
	var scanResetKeyAt pq.NullTime

	err = self.db.QueryRow(query, userId).Scan(
		&user.createdAt,
		&user.email,
		&user.hashedPass,
		&user.lang,
		&user.confirmationKey,
		&scanConfirmedAt,
		&scanResetKey,
		&scanResetKeyAt,
	)

	if scanConfirmedAt.Valid {
		user.confirmedAt = scanConfirmedAt.Time
	}
	if scanResetKey.Valid {
		user.resetKey = scanResetKey.String
	}
	if scanResetKeyAt.Valid {
		user.resetKeyAt = scanResetKeyAt.Time
	}

	return
}

func (self storePg) getAllUsers() (users []User, err error) {
	query := `
		SELECT id, createdAt, email, lang, confirmedAt
		FROM auth.user;
	`

	var scanConfirmedAt pq.NullTime

	rows, err := self.db.Query(query)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		user := User{}
		err = rows.Scan(&user.Id, &user.CreatedAt, &user.Email, &user.Lang, &scanConfirmedAt)
		if err != nil {
			return
		}
		if scanConfirmedAt.Valid {
			user.ConfirmedAt = scanConfirmedAt.Time
		}
		users = append(users, user)
	}
	err = rows.Err()
	return
}

func (self storePg) createSession(sessionId, userId string, activityAt time.Time) error {
	insert := `
		INSERT INTO auth.session
		(id, userId, activityAt)
		VALUES
		($1, $2, $3);
	`

	stmt, err := self.db.Prepare(insert)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(sessionId, userId, activityAt)
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
		SELECT userId, activityAt
		FROM auth.session
		WHERE id = $1;
	`
	err = self.db.QueryRow(query, sessionId).Scan(&session.userId, &session.activityAt)
	return
}

func (self storePg) removeUnconfirmedUsersCreatedBefore(date time.Time) error {
	stmt, err := self.db.Prepare("DELETE FROM auth.user WHERE createdAt < $1;")
	if err != nil {
		return err
	}

	_, err = stmt.Exec(date)
	return err
}

func (self storePg) removeSessionsIdleBefore(date time.Time) error {
	stmt, err := self.db.Prepare("DELETE FROM auth.session WHERE activityAt < $1;")
	if err != nil {
		return err
	}

	_, err = stmt.Exec(date)
	return err
}
