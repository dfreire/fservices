package mail

type SendRequest struct {
	From        string
	To          []string
	Cc          []string
	Bcc         []string
	Subject     string
	Text        string
	Html        string
	Attachments []string
}

type Mail interface {
	Send(request SendRequest) error
}
