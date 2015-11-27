package mailer

import (
	"net/smtp"
	"strconv"
	"strings"

	"github.com/jordan-wright/email"
)

type Mailer interface {
	QuickSend(from, to, subject, body string) error
	Send(from string, to, cc, bcc []string, subject, body string, attachements []string) error
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

func (self mailerImpl) QuickSend(from, to, subject, body string) error {
	return self.Send(from, []string{to}, nil, nil, subject, body, nil)
}

func (self mailerImpl) Send(from string, to, cc, bcc []string, subject, body string, attachments []string) error {
	e := email.NewEmail()
	if from != "" {
		e.From = from
	} else {
		e.From = self.cfg.Email
	}
	e.To = to
	e.Cc = cc
	e.Bcc = bcc
	e.Subject = subject
	e.HTML = []byte(body)

	for _, attachment := range attachments {
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
