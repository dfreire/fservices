package auth

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

type storeSqlite struct {
	db *sql.DB
}

func NewStoreSqlite(db *sql.DB) storeSqlite {
	return storeSqlite{db}
}

func (self storeSqlite) createSchema() error {
	schema := `
		CREATE TABLE auth_user (
		   id              CHAR(36) NOT NULL,
		   createdAt       DATETIME NOT NULL,
		   email           TEXT NOT NULL,
		   hashedPass      TEXT NOT NULL,
		   lang            CHAR(5) NOT NULL,
		   confirmationKey CHAR(36) NOT NULL,
		   confirmedAt     DATETIME,
		   resetKey        CHAR(36),

		   CONSTRAINT pk_auth_user PRIMARY KEY (id)
		);

		CREATE UNIQUE INDEX idx_auth_user_email ON auth_user (email);
	`

	_, err := self.db.Exec(schema)
	return err
}

func (self storeSqlite) createUser(userId string, createdAt time.Time, email, hashedPass, lang, confirmationKey string) error {
	insert := `
		INSERT INTO auth_user
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

func (self storeSqlite) removeUsers(userIds ...string) error {
	placeholders := make([]string, len(userIds))
	arguments := make([]interface{}, len(userIds))
	for i, argument := range userIds {
		s := strconv.Itoa(i + 1)
		placeholders[i] = strings.Join([]string{"$", s}, "")
		arguments[i] = argument
	}

	delete := fmt.Sprintf("DELETE FROM auth_user WHERE id IN (%s)", strings.Join(placeholders, ","))
	stmt, err := self.db.Prepare(delete)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(arguments...)
	return err
}

func (self storeSqlite) setUserConfirmedAt(userId string, confirmedAt time.Time) error {
	update := `
		UPDATE auth_user
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

func (self storeSqlite) setUserResetKey(userId, resetKey string) error {
	update := `
		UPDATE auth_user
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

func (self storeSqlite) setUserHashedPass(userId, hashedPass string) error {
	update := `
		UPDATE auth_user
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

func (self storeSqlite) setUserEmail(userId, email string) error {
	update := `
		UPDATE auth_user
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

func (self storeSqlite) getUserId(email string) (userId string, err error) {
	query := `
		SELECT id
		FROM auth_user
		WHERE email = $1;
	`
	err = self.db.QueryRow(query, email).Scan(&userId)
	return
}

func (self storeSqlite) getPrivateUser(userId string) (user privateUser, err error) {
	user.id = userId

	query := `
		SELECT createdAt, email, hashedPass, lang, confirmationKey, confirmedAt, resetKey
		FROM auth_user
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

func (self storeSqlite) getAllUsers() (users []User, err error) {
	query := `
		SELECT id, createdAt, email, lang, confirmedAt
		FROM auth_user;
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

func (self storeSqlite) removeUnconfirmedUsersCreatedBefore(date time.Time) error {
	stmt, err := self.db.Prepare("DELETE FROM auth_user WHERE createdAt < $1;")
	if err != nil {
		return err
	}

	_, err = stmt.Exec(date)
	return err
}
