package vault

import (
	"fmt"
	"regexp"

	"github.com/elliottsam/vault-config/crypto"
)

var wrappedCipherRegex = regexp.MustCompile(`@encrypted_data\((.*)\)`)

type Secret struct {
	Name string                 `hcl:",key"`
	Path string                 `hcl:"path"`
	Data map[string]interface{} `hcl:"data"`
}

func (c *VCClient) WriteSecret(s Secret) error {
	_, err := c.Logical().Write(s.Path, s.Data)
	if err != nil {
		return fmt.Errorf("Writing secret: %s\nError: %v", s.Name, err)
	}

	return nil
}

func (c *VCClient) secretExist(s Secret) bool {
	secret, err := c.Logical().Read(s.Path)
	if err != nil || secret == nil {
		return false
	}

	return true
}

func (c *Config) DecryptSecrets(key []byte) error {
	var err error
	for _, s := range c.Secrets {
		for k, v := range s.Data {
			switch v.(type) {
			case string:
				if wrappedCipherRegex.MatchString(v.(string)) {
					s.Data[k], err = crypto.DecryptString(v.(string), key)
					if err != nil {
						return fmt.Errorf("Error decrypting secret: %s\nErr: %v", s.Path, err)
					}
				}
			}
		}
	}
	return nil
}

// SecretsEncrypted will search a slice of secrets for encryption strings and return true if found
func SecretsEncrypted(c Config) (sf bool) {
	for _, v := range c.Secrets {
		for _, v := range v.Data {
			switch v.(type) {
			case string:
				if wrappedCipherRegex.MatchString(v.(string)) {
					sf = true
				}
			}
		}
	}
	for _, v := range c.Auth.Ldap.AuthConfig {
		switch v.(type) {
		case string:
			if wrappedCipherRegex.MatchString(v.(string)) {
				sf = true
			}
		}
	}

	return
}
