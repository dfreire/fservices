package auth

import "errors"

type Store interface {
	CreateUser(appId, email, hashedPass, confirmationToken string) error
}

var ErrUserEmailExists = errors.New("This email is already being used.")
