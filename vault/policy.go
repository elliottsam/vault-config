package vault

import (
	"log"
)

// PolicyExists checks for the existence of a policy
func (c *VCClient) PolicyExist(name string) bool {
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

// PolicyAdd adds a new policy
func (c *VCClient) PolicyAdd(p policies) error {
	err := c.Sys().PutPolicy(p.Name, p.Rules)
	if err != nil {
		return err
	}

	return nil
}
