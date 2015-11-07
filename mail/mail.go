package mail

type SendMailRequest struct {
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
	SendMail(request SendMailRequest) error
}
