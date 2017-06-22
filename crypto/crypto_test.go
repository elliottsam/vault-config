package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	str         = `This is a test string`
	cipherRegex = `@encrypted_data\((.*)\)`
	hmacRegex   = `@hmac\((.*)\)`
)

var (
	key = []byte{153, 43, 36, 168, 16, 188, 230, 176, 58, 230, 90, 31, 60, 230, 144, 113, 91, 99, 142, 113, 201, 215, 170, 200, 251, 250, 234, 101, 249, 1, 194, 171}
	e   = EncryptionObject{
		Key:       key,
		PlainText: []byte(str),
	}
	newe = EncryptionObject{
		Key: key,
	}
)

func TestEncryptionObject_Encrypt(t *testing.T) {
	err := e.Encrypt()
	assert.NoError(t, err, "Should complete without error")

	h, _ := CreateHMAC(e.Key, e.CipherText)
	assert.Equal(t, e.HMAC, h, "HMACS should equal the same")
	e.WrapCrypto()
	assert.Regexp(t, cipherRegex, e.WrappedData, "Regex should match wrapped text")
	assert.Regexp(t, hmacRegex, e.WrappedData, "Regex should match wrapped text")
}

func TestEncryptionObject_Decrypt(t *testing.T) {
	newe.WrappedData = e.WrappedData
	err := newe.UnwrapCrypto()
	assert.NoError(t, err, "Unwrap should return no errors")
	err = nil
	err = newe.Decrypt()
	assert.NoError(t, err, "Decryption should have no errors")
	assert.Equal(t, str, string(newe.PlainText), "Decrypted string should match original string")
}

func TestRandomKey(t *testing.T) {
	a := RandomKey(32)
	b := RandomKey(32)
	assert.Equal(t, 32, len(a), "Length of generated string should be 32")
	assert.NotEqual(t, a, b, "Two different keys should not be the same")
}
