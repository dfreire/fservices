package mailer

import (
	"net/smtp"
	"strconv"
	"strings"

	"github.com/jordan-wright/email"
)

type Mailer interface {
	Send(Mail) error
}

type mailerImpl struct {
	cfg SmtpConfig
}

type SmtpConfig struct {
	Host     string
	Port     int
	Email    string
	Password string
}

func NewMailer(cfg SmtpConfig) mailerImpl {
	return mailerImpl{cfg}
}

func (self mailerImpl) Send(mail Mail) error {
	e := email.NewEmail()
	if mail.From != "" {
		e.From = mail.From
	} else {
		e.From = self.cfg.Email
	}
	e.To = mail.To
	e.Cc = mail.Cc
	e.Bcc = mail.Bcc
	e.Subject = mail.Subject
	e.HTML = []byte(mail.Body)

	for _, attachment := range mail.Attachments {
		e.AttachFile(attachment)
	}

	hostAndPort := strings.Join([]string{
		self.cfg.Host,
		strconv.Itoa(self.cfg.Port),
	}, ":")

	plainAuth := smtp.PlainAuth(
		"", // identity
		self.cfg.Email,
		self.cfg.Password,
		self.cfg.Host,
	)

	return e.Send(hostAndPort, plainAuth)
}
