package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExecute(t *testing.T) {
	_, err := RootCmd.ExecuteC()

	assert.NoError(t, err, "Running configCmd should return no error")
}
