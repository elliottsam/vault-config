package vault

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/mgutz/logxi/v1"
)

func (c *VCClient) TokenRoleExists(name string) bool {
	r, err := c.Logical().List("auth/token/roles")
	if err != nil {
		log.Fatal("Error reading roles:", err)
	}
	//TODO Remove the spew below
	spew.Dump(r.Data)
	if _, ok := r.Data[name]; ok {
		return true
	}

	return false
}

func (c *VCClient) WriteTokenRole(name string, data map[string]interface{}) error {
	p := fmt.Sprintf("auth/token/roles/%s", name)
	_, err := c.Client.Logical().Write(p, data)
	if err != nil {
		return fmt.Errorf("Error writing role: %v", err)
	}

	return nil
}
