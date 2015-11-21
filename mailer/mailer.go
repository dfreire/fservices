package mailer

import (
	"net/smtp"
	"strconv"
	"strings"

	"github.com/jordan-wright/email"
)

type Mailer interface {
	Send(request SendMailRequest) error
}

type SendMailRequest struct {
	From        string
	To          []string
	Cc          []string
	Bcc         []string
	Subject     string
	Body        string
	Attachments []string
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

func (self mailerImpl) Send(request SendMailRequest) error {
	e := email.NewEmail()

	if request.From != "" {
		e.From = request.From
	} else {
		e.From = self.cfg.Email
	}

	e.To = request.To
	e.Cc = request.Cc
	e.Bcc = request.Bcc
	e.Subject = request.Subject
	e.HTML = []byte(request.Body)

	for _, attachment := range request.Attachments {
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
