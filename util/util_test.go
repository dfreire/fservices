package util

import (
	"testing"

	"github.com/dfreire/fservices/util"
	"github.com/stretchr/testify/assert"
)

func TestRenderTemplate(t *testing.T) {
	templateString := "Hello, {{.Value}}!"
	templateValues := struct{ Value string }{"world"}

	actual, err := util.RenderTemplate(templateString, templateValues)

	assert.Nil(t, err)
	assert.Equal(t, "Hello, world!", actual)
}
