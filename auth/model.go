package auth

import "time"

type User struct {
	AppId              string
	UserId             string
	Email              string
	HashedPass         string
	CreatedAt          time.Time
	ConfirmedAt        time.Time
	ConfirmationToken  string
	RequestedResetAt   time.Time
	ResetToken         string
	MustChangePassword bool
}

type Session struct {
	AppId     string
	UserId    string
	CreatedAt time.Time
}
