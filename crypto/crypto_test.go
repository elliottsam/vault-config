package crypto

import (
	"testing"

	"github.com/hashicorp/hcl"
	"github.com/stretchr/testify/assert"
)

const (
	str         = `This is a test string`
	cipherRegex = `@encrypted_data\((.*)\)`
	hmacRegex   = `@hmac\((.*)\)`
	secretHCL   = `secret "test" {
  path = "secret/test"

  data {
    value  = "test_value1"
    value2 = "test_value2"
  }
}`
)

type secret struct {
	Name string                 `hcl:",key"`
	Path string                 `hcl:"path"`
	Data map[string]interface{} `hcl:"data"`
}

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

func TestStringEncryption(t *testing.T) {
	es, err := EncryptString(str, key)
	assert.NoError(t, err, "No error should occur when encrypting string")
	assert.Regexp(t, cipherRegex, es, "Cipher text should match regex")
	ps, err := DecryptString(es, key)
	assert.NoError(t, err, "No error should occur when decrypting string")
	assert.Equal(t, str, ps, "Decrypted string should match original string")
}

func TestInlineEncryptSecrets(t *testing.T) {
	var (
		originalObject  secret
		encryptedObject secret
	)
	e := EncryptionObject{
		Key:       key,
		PlainText: []byte(secretHCL),
	}
	hcl.Unmarshal([]byte(secretHCL), &originalObject)

	err := e.InlineEncryptMap("string/data")
	assert.NoError(t, err, "No error should occur whilst encrypting data")
	hcl.Unmarshal(e.CipherText, &encryptedObject)

	for k, v := range encryptedObject.Data {
		assert.Regexp(t, cipherRegex, v.(string), "Values should have been encrypted")
		v, err = DecryptString(v.(string), key)
		assert.NoError(t, err, "No errors should occur decrypting string")
		assert.Equal(t, originalObject.Data[k], v, "After decryption values should match")
	}
	assert.Equal(t, originalObject, encryptedObject, "Secre objects should match")
}
