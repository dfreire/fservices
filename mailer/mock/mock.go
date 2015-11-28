package mock

import (
	"github.com/dfreire/fservices/mailer"
	"github.com/stretchr/testify/mock"
)

type MailerMock struct {
	mock.Mock
}

func (m *MailerMock) Send(mail mailer.Mail) error {
	args := m.Called(mail)
	return args.Error(0)
}
