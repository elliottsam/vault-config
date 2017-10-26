package vault

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
)

// VCClient is a wrapper around the Vault api.Client
type VCClient struct {
	*api.Client
}

// Config contains the Vault configuration that will be
// applied to the server
type Config struct {
	Mounts     []Mount     `hcl:"mount"`
	Policies   []Policy    `hcl:"policy"`
	TokenRoles []TokenRole `hcl:"token_role"`
	Auth       Auth        `hcl:"auth"`
	Secrets    []Secret    `hcl:"secret"`
}

type Mount struct {
	Name   string `hcl:",key"`
	Path   string `hcl:"path"`
	Config struct {
		PathType    string `hcl:"type" mapstructure:"type"`
		Description string `hcl:"description" mapstructure:"description"`
		MountConfig struct {
			DefaultLeaseTTL string `hcl:"default_lease_ttl" mapstructure:"default_lease_ttl"`
			MaxLeaseTTL     string `hcl:"max_lease_ttl" mapstructure:"max_lease_ttl"`
		} `hcl:"mountconfig"`
	} `hcl:"config"`
}

type Policy struct {
	Name  string `hcl:",key"`
	Rules string `hcl:"rules"`
}

type Auth struct {
	Ldap   *Ldap   `hcl:"ldap"`
	Github *Github `hcl:"github"`
}

type TokenRole struct {
	Name    string                 `hcl:",key"`
	Options map[string]interface{} `hcl:"options"`
}

// NewClient returns a Vault client
func NewClient(c *api.Config) (*VCClient, error) {
	if c == nil {
		c = api.DefaultConfig()
		if os.Getenv("VAULT_SKIP_VERIFY") == "true" {
			if err := c.ConfigureTLS(&api.TLSConfig{Insecure: true}); err != nil {
				return nil, err
			}
		}
	}
	client, err := api.NewClient(c)
	if err != nil {
		return nil, err
	}

	return &VCClient{client}, nil
}

// WalkVault will go through a specific path and return the path of all secrets
func (c *VCClient) WalkVault(path string) (output []string, err error) {
	s, err := c.Logical().List(path)
	if err != nil || s == nil {
		err = fmt.Errorf("Error reading Vault path: %s", path)
		return
	}
	for _, a := range s.Data {
		for _, v := range a.([]interface{}) {
			if strings.HasSuffix(v.(string), "/") {
				sp, err := c.WalkVault(fmt.Sprintf("%s/%s", path, strings.TrimSuffix(v.(string), "/")))
				if err != nil {
					err = fmt.Errorf("Error reading Vault path: %s/%s", path, v.(string))
					return output, err
				}
				output = append(output, sp...)
			} else {
				output = append(output, fmt.Sprintf("%s/%s", path, v.(string)))
			}
		}
	}

	return
}
