package vault

import (
	"fmt"

	"github.com/fatih/structs"
)

type Ldap struct {
	Description string                 `hcl:"description"`
	AuthConfig  map[string]interface{} `hcl:"authconfig"`
	Users       []struct {
		Name    string                 `hcl:",key"`
		Options map[string]interface{} `hcl:"options"`
	} `hcl:"User"`
	Groups []struct {
		Name    string                 `hcl:",key"`
		Options map[string]interface{} `hcl:"options"`
	} `hcl:"group"`
	MountConfig struct {
		DefaultLeaseTTL string `hcl:"default_lease_ttl" mapstructure:"default_lease_ttl"`
		MaxLeaseTTL     string `hcl:"max_lease_ttl" mapstructure:"max_lease_ttl"`
	} `hcl:"mountconfig"`
}

func (l Ldap) GetType() string {
	return "ldap"
}

func (l Ldap) Describe() string {
	return l.Description
}

func (l Ldap) TuneMount(c *VCClient, path string) error {
	return c.TuneMount(path, structs.Map(l.MountConfig))
}

func (l Ldap) WriteUsers(c *VCClient) error {
	userPath := fmt.Sprintf("%s/users", Path(l))
	for _, v := range l.Users {
		if v.Name != "" {
			path := fmt.Sprintf("%s/%s", userPath, v.Name)
			_, err := c.Logical().Write(path, v.Options)
			if err != nil {
				return fmt.Errorf("Error writing value to Vault: %v", err)
			}
		}
	}

	return nil
}

func (l Ldap) WriteGroups(c *VCClient) error {
	groupPath := fmt.Sprintf("%s/groups", Path(l))

	for _, v := range l.Groups {
		path := fmt.Sprintf("%s/%s", groupPath, v.Name)
		_, err := c.Logical().Write(path, v.Options)
		if err != nil {
			return fmt.Errorf("Error writing value to Vault: %v", err)
		}
	}

	return nil
}

func (l Ldap) Configure(c *VCClient) error {
	path := fmt.Sprintf("%s/config", Path(l))
	_, err := c.Logical().Write(path, l.AuthConfig)
	if err != nil {
		return fmt.Errorf("Error writing auth config: %v", err)
	}

	return nil
}

func (l Ldap) getAuthConfig() map[string]interface{} {
	return l.AuthConfig
}

func (l Ldap) getAuthMountConfig() map[string]interface{} {
	return ConvertMapStringInterface(l.MountConfig)
}