package mock

import "github.com/stretchr/testify/mock"

type MailerMock struct {
	mock.Mock
}

func (m *MailerMock) QuickSend(from, to, subject, body string) error {
	args := m.Called(from, to, subject, body)
	return args.Error(0)
}

func (m *MailerMock) Send(from string, to, cc, bcc []string, subject, body string, attachments []string) error {
	args := m.Called(from, to, cc, bcc, subject, body, attachments)
	return args.Error(0)
}
