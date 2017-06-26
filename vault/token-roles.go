package vault

import "fmt"

func (c *VCClient) tokenRoleExists(tr TokenRole) bool {
	path := fmt.Sprintf("auth/token/roles/%s", tr.Name)
	r, err := c.Logical().Read(path)
	if err != nil || r == nil {
		return false
	}

	return true
}

func (c *VCClient) WriteTokenRole(tr TokenRole) error {
	path := fmt.Sprintf("auth/token/roles/%s", tr.Name)
	_, err := c.Client.Logical().Write(path, tr.Options)
	if err != nil {
		return fmt.Errorf("Error writing role: %v", err)
	}

	return nil
}
