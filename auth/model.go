package auth

import "time"

type User struct {
	UserId            string
	AppId             string
	Email             string
	HashedPass        string
	CreatedAt         time.Time
	IsConfirmed       bool
	ConfirmationToken string
}
