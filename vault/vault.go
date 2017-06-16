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
}

type Mount struct {
	Name   string `hcl:",key"`
	Path   string `hcl:"path"`
	Config struct {
		PathType    string `hcl:"type" mapstructure:"type"`
		Description string `hcl:"description" mapstructure:"description"`
	} `hcl:"config"`
	MountConfig struct {
		DefaultLeaseTTL string `hcl:"default_lease_ttl" mapstructure:"default_lease_ttl"`
		MaxLeaseTTL     string `hcl:"max_lease_ttl" mapstructure:"max_lease_ttl"`
		ForceNoCache    bool   `hcl:"force_no_cache" mapstructure:"force_no_cache"`
	} `hcl:"mountconfig"`
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
	Name    string `hcl:",key"`
	Options struct {
		AllowedPolicies    string `hcl:"allowed_policies" mapstructure:"allowed_policies"`
		DisallowedPolicies string `hcl:"disallowed_policies" mapstructure:"disallowed_policies"`
		ExplicitMaxTTL     int    `hcl:"explicit_max_ttl" mapstructure:"explicit_max_ttl"`
		Orphan             bool   `hcl:"orphan" mapstructure:"orphan"`
		PathSuffix         string `hcl:"path_suffix" mapstructure:"path_suffix"`
		Period             int    `hcl:"period" mapstructure:"period"`
		Renewable          bool   `hcl:"renewable" mapstructure:"renewable"`
	} `hcl:"options"`
}

// NewClient returns a Vault client
func NewClient(c *api.Config) (*VCClient, error) {
	client, err := api.NewClient(c)
	if err != nil {
		return nil, err
	}

	return &VCClient{client}, nil
}
