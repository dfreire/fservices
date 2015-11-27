package auth2

import (
	"database/sql"
	"time"

	_ "github.com/lib/pq"
)

type store interface {
	createUser(id, appId, email, hashedPass, lang, confirmationKey string, createdAt time.Time) error
}

type storePg struct {
	db *sql.DB
}

func NewStorePg(db *sql.DB) (storePg, error) {
	impl := storePg{db}
	return impl, impl.createSchema()
}

func (self storePg) createSchema() error {
	schema := `
		CREATE SCHEMA auth;

		CREATE TYPE auth.lang AS ENUM ('pt_PT', 'en_US');

		CREATE TABLE auth.user (
		   id                       CHAR(36) PRIMARY KEY NOT NULL,
		   appId                    TEXT NOT NULL,
		   email                    TEXT NOT NULL,
		   hashedPass               TEXT NOT NULL,
		   createdAt                TIMESTAMPTZ NOT NULL,
		   lang                     auth.lang NOT NULL,
		   -- confirm
		   confirmationKey          CHAR(36),
		   requestedConfirmationAt  TIMESTAMPTZ,
		   confirmedAt              TIMESTAMPTZ,
		   -- reset
		   resetToken               CHAR(36),
		   sentResetTokenAt         TIMESTAMPTZ
		);

		CREATE UNIQUE INDEX auth_user_appId_email ON auth.user (appId, email);
	`

	_, err := self.db.Exec(schema)
	return err
}

func (self storePg) createUser(id, appId, email, hashedPass, lang, confirmationKey string, createdAt time.Time) error {
	insert := `
		INSERT INTO auth.user
		(id, appId, email, hashedPass, lang, confirmationKey, createdAt)
		VALUES
		($1, $2, $3, $4, $5, $6, $7);
	`

	stmt, err := self.db.Prepare(insert)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(id, appId, email, hashedPass, lang, confirmationKey, createdAt)
	return err
}
