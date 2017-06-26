package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExecute(t *testing.T) {
	err := RootCmd.Execute()

	assert.NoError(t, err, "Running configCmd should return no error")
}
