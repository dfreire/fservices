package auth

import (
	"github.com/dfreire/fservices/mail"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type SignupRequest struct {
	AppId                            string
	Email                            string
	Password                         string
	ConfirmationEmailSubjectTemplate string
	ConfirmationEmailBodyTemplate    string
}

func Signup(store Store, mail mail.Mail, request SignupRequest) error {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	confirmationToken := uuid.NewV4().String()

	if err := store.CreateUser(request.AppId, request.Email, string(hashedPass), confirmationToken); err != nil {
		return err
	}

	if err := mail.Send(request.Email, "Confirm Registration", "Please confirm your registration"); err != nil {
		return err
	}

	return nil
}
