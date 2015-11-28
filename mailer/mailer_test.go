package mailer

import (
	"log"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/renstrom/shortuuid"
	"github.com/stretchr/testify/assert"
)

type mailinatorInbox struct {
	Messages []struct {
		Id      string
		From    string
		To      string
		Subject string
	}
}

type mailinatorEmail struct {
	Data struct {
		Parts []struct {
			Body string
		}
	}
}

func TestSend(t *testing.T) {
	var cfg SmtpConfig
	_, err := toml.DecodeFile("mailer_test.secret.toml", &cfg)

	if assert.Nil(t, err) {
		mail := Mail{
			From:    randomMailinatorAddress(),
			To:      []string{randomMailinatorAddress()},
			Subject: strings.Join([]string{"Test", shortuuid.UUID()}, "-"),
			Body:    strings.Join([]string{"<h1>", shortuuid.UUID(), "</h1>"}, ""),
		}
		mailer := NewMailer(cfg)
		err = mailer.Send(mail)

		if assert.Nil(t, err) {
			log.Printf("Sent mail %+v", mail)
			// https://api.mailinator.com/api/inbox?to=YYU42xSambKiB2EAtTg8xS@mailinator.com
			// https://api.mailinator.com/api/email?msgid=1448108946-77611349-kquawg
		}
	}
}

func randomMailinatorAddress() string {
	return strings.Join([]string{shortuuid.UUID(), "@mailinator.com"}, "")
}
