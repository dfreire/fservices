package auth

import "time"

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
