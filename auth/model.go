package auth

import "time"

type User struct {
	AppId              string
	UserId             string
	Email              string
	HashedPass         string
	CreatedAt          time.Time
	Confirmed          bool
	ConfirmationToken  string
	RequestedReset     bool
	ResetToken         string
	RequestedResetAt   time.Time
	MustChangePassword bool
}

type Session struct {
	AppId     string
	UserId    string
	CreatedAt time.Time
}
