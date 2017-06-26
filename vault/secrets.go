package vault

import "fmt"

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
