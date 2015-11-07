package mail

type Mail interface {
	Send(to, subject, body string) error
}
