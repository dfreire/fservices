package auth

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

type User struct {
	Id          string
	CreatedAt   time.Time
	Email       string
	Lang        string
	ConfirmedAt time.Time
}

type privateUser struct {
	id              string
	createdAt       time.Time
	email           string
	hashedPass      string
	lang            string
	confirmationKey string
	confirmedAt     time.Time
	resetKey        string
}

type store interface {
	createSchema() error

	createUser(userId string, createdAt time.Time, email, hashedPass, lang, confirmationKey string) error
	removeUsers(userIds ...string) error
	setUserConfirmedAt(userId string, confirmedAt time.Time) error
	setUserResetKey(userId, resetKey string) error
	setUserHashedPass(userId, hashedPass string) error
	setUserEmail(userId, email string) error
	getUserId(email string) (userId string, err error)
	getPrivateUser(userId string) (user privateUser, err error)
	getAllUsers() (users []User, err error)

	removeUnconfirmedUsersCreatedBefore(date time.Time) error
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

		   CONSTRAINT pk_auth_user PRIMARY KEY (id)
		);

		CREATE UNIQUE INDEX idx_auth_user_email ON auth.user (email);
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

func (self storePg) removeUsers(userIds ...string) error {
	placeholders := []string{}
	var arguments []interface{}
	for i, argument := range userIds {
		s := strconv.Itoa(i + 1)
		placeholders = append(placeholders, strings.Join([]string{"$", s}, ""))
		arguments = append(arguments, argument)
	}

	delete := fmt.Sprintf("DELETE FROM auth.user WHERE id IN (%s)", strings.Join(placeholders, ","))
	stmt, err := self.db.Prepare(delete)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(arguments...)
	return err
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

func (self storePg) setUserResetKey(userId, resetKey string) error {
	update := `
		UPDATE auth.user
		SET resetKey = $1
		WHERE id = $2;
	`

	stmt, err := self.db.Prepare(update)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(resetKey, userId)
	return err
}

func (self storePg) setUserHashedPass(userId, hashedPass string) error {
	update := `
		UPDATE auth.user
		SET hashedPass = $1, resetKey = NULL
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

func (self storePg) getPrivateUser(userId string) (user privateUser, err error) {
	user.id = userId

	query := `
		SELECT createdAt, email, hashedPass, lang, confirmationKey, confirmedAt, resetKey
		FROM auth.user
		WHERE id = $1;
	`

	var scanConfirmedAt pq.NullTime
	var scanResetKey sql.NullString

	err = self.db.QueryRow(query, userId).Scan(
		&user.createdAt,
		&user.email,
		&user.hashedPass,
		&user.lang,
		&user.confirmationKey,
		&scanConfirmedAt,
		&scanResetKey,
	)

	if scanConfirmedAt.Valid {
		user.confirmedAt = scanConfirmedAt.Time
	}
	if scanResetKey.Valid {
		user.resetKey = scanResetKey.String
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

func (self storePg) removeUnconfirmedUsersCreatedBefore(date time.Time) error {
	stmt, err := self.db.Prepare("DELETE FROM auth.user WHERE createdAt < $1;")
	if err != nil {
		return err
	}

	_, err = stmt.Exec(date)
	return err
}
