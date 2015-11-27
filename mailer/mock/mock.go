package mock

import (
	"github.com/dfreire/fservices/mailer"
	"github.com/stretchr/testify/mock"
)

type MailerMock struct {
	mock.Mock
}

func (m *MailerMock) Send(request mailer.SendMailRequest) error {
	args := m.Called(request)
	return args.Error(0)
}
