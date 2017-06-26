package vault

import "github.com/hashicorp/vault/api"

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
	client, err := api.NewClient(c)
	if err != nil {
		return nil, err
	}

	return &VCClient{client}, nil
}
