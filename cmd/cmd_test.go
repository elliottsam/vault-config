package cmd

import (
	"testing"

	"log"

	"github.com/stretchr/testify/assert"
)

func TestExecute(t *testing.T) {
	err := RootCmd.Execute()
	log.Println(err)

	assert.NoError(t, err, "Running configCmd should return no error")
}
