package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	mrand "math/rand"
	"regexp"
	"time"
)

var (
	wrappedCipherRegex = regexp.MustCompile(`@encrypted_data\((.*)\)`)
	wrappedHmacRegex   = regexp.MustCompile(`@hmac\((.*)\)`)
)

// EncryptionObject contains all the variables and methods
// associated with encrypting and decrypting data
type EncryptionObject struct {
	Key         string
	CipherText  []byte
	PlainText   []byte
	HMAC        []byte
	WrappedData string
}

// Encrypt will crypto data with specified key
func (e *EncryptionObject) Encrypt() error {
	keyb := []byte(e.Key)

	block, err := aes.NewCipher(keyb)
	if err != nil {
		return fmt.Errorf("Error creating AES block: %v", err)
	}

	e.CipherText = make([]byte, aes.BlockSize+len(e.PlainText))
	iv := e.CipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("Error creating iv: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(e.CipherText[aes.BlockSize:], e.PlainText)
	e.HMAC, err = CreateHMAC(e.Key, e.CipherText)
	if err != nil {
		return fmt.Errorf("Creating HMAC: %v", err)
	}
	e.WrapCrypto()

	return nil
}

// Decrypt will decrypt data with specified key
func (e *EncryptionObject) Decrypt() error {
	bkey := []byte(e.Key)

	h, _ := CreateHMAC(e.Key, e.CipherText)
	if !hmac.Equal(e.HMAC, h) {
		return fmt.Errorf("HMAC failure, ciphertext has changed, this could indicate incorrect key")
	}

	block, err := aes.NewCipher(bkey)
	if err != nil {
		return fmt.Errorf("Error creating AES block: %v", err)
	}

	iv := e.CipherText[:aes.BlockSize]
	e.CipherText = e.CipherText[aes.BlockSize:]

	e.PlainText = make([]byte, len(e.CipherText))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(e.PlainText, e.CipherText)

	return nil
}

// CreateHMAC will generate a cryptographic hash of data supplied
func CreateHMAC(key string, data []byte) ([]byte, error) {
	keyb := []byte(key)

	h := hmac.New(sha512.New, keyb)
	_, err := h.Write(data)
	if err != nil {
		return nil, fmt.Errorf("Error writing data for HMAC: %v", err)
	}

	return h.Sum(nil), nil
}

// WrapCrypto wraps both cipher text and hmac into a single string
// to be written to disk
func (e *EncryptionObject) WrapCrypto() {
	b64cipher := base64.StdEncoding.EncodeToString(e.CipherText)
	b64hmac := base64.StdEncoding.EncodeToString(e.HMAC)

	e.WrappedData = fmt.Sprintf("@encrypted_data(%s)\n@hmac(%s)", b64cipher, b64hmac)
}

//UnwrapCrypto unwraps cipher text and hmac to allow decryption
func (e *EncryptionObject) UnwrapCrypto() error {
	var err error

	b64cipher := wrappedCipherRegex.FindStringSubmatch(e.WrappedData)
	if b64cipher == nil || len(b64cipher) < 1 || b64cipher[1] == "" {
		return fmt.Errorf("unwrapping cipher text")
	}

	e.CipherText, err = base64.StdEncoding.DecodeString(b64cipher[1])
	if err != nil {
		return fmt.Errorf("decoding base64 cipher: %v", err)
	}

	b64hmac := wrappedHmacRegex.FindStringSubmatch(e.WrappedData)
	if b64hmac == nil || len(b64hmac) < 1 || b64hmac[1] == "" {
		return fmt.Errorf("unwrapping HMAC text")
	}

	e.HMAC, err = base64.StdEncoding.DecodeString(b64hmac[1])
	if err != nil {
		return fmt.Errorf("decoding base64 HMAC: %v", err)
	}

	return nil
}

// RandomKey returns a random password of specified length
func RandomKey(n int) string {
	const chars = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`
	b := make([]byte, n)

	rdm := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	for i := range b {
		b[i] = chars[rdm.Intn(len(chars))]
	}

	return string(b)
}
