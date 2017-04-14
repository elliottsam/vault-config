package vault

import (
	"log"
)

func (c *VaultClient) PolicyExist(name string) bool {
	pol, err := c.Sys().ListPolicies()
	if err != nil {
		log.Fatalf("Error listing policies: %v", err)
	}

	for _, v := range pol {
		if v == name {
			return true
		}
	}

	return false
}

func (c *VaultClient) PolicyAdd(p policies) error {
	err := c.Sys().PutPolicy(p.Name, p.Rules)
	if err != nil {
		return err
	}

	return nil
}
