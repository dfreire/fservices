package auth

import (
	"github.com/dfreire/fservices/mail"
	"github.com/dfreire/fservices/util"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type SignupRequest struct {
	AppId             string
	Email             string
	Password          string
	EmailFrom         string
	EmailSubject      string
	EmailHtmlTemplate string
}

func Signup(store Store, mailService mail.Mail, request SignupRequest) (confirmationToken string, err error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	confirmationToken = uuid.NewV4().String()
	templateValues := struct{ ConfirmationToken string }{confirmationToken}
	html, err := util.RenderTemplate(request.EmailHtmlTemplate, templateValues)
	if err != nil {
		return "", err
	}

	if err := store.CreateUser(request.AppId, request.Email, string(hashedPass), confirmationToken); err != nil {
		return "", err
	}

	mailSendRequest := mail.SendRequest{
		From:    request.EmailFrom,
		To:      []string{request.Email},
		Subject: request.EmailSubject,
		Html:    html,
	}

	if err := mailService.Send(mailSendRequest); err != nil {
		return "", err
	}

	return confirmationToken, nil
}
