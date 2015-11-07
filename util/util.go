package util

import (
	"bytes"
	"html/template"
	"strings"
)

func RenderTemplate(templateString string, templateValues interface{}) (string, error) {
	t, err := template.New("").Parse(strings.Join([]string{
		"{{define \"T\"}}",
		templateString,
		"{{end}}",
	}, ""))
	if err != nil {
		return "", err
	}

	var out bytes.Buffer
	if err = t.ExecuteTemplate(&out, "T", templateValues); err != nil {
		return "", err
	}

	return out.String(), nil
}
