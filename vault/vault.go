package vault

import "github.com/hashicorp/vault/api"

// VCClient is a wrapper around the Vault api.Client
type VCClient struct {
	*api.Client
}

// VCConfig contains the Vault configuration that will be
// applied to the server
type VCConfig struct {
	Mount  []mounts   `hcl:"mounts,ommitempty"`
	Policy []policies `hcl:"policies,ommitempty"`
	Auth   []auth     `hcl:"auth,ommitempty"`
}

type mounts struct {
	Path   string      `hcl:"path,ommitempty"`
	Config *mountInput `hcl:"config,ommitempty"`
}

type mountInput struct {
	Type        string           `hcl:"type" structs:"type"`
	Description string           `hcl:"description" structs:"description"`
	Config      mountConfigInput `hcl:"mountconfig" structs:"config"`
}

type mountConfigInput struct {
	DefaultLeaseTTL string `hcl:"default_lease_ttl" structs:"default_lease_ttl" mapstructure:"default_lease_ttl"`
	MaxLeaseTTL     string `hcl:"max_lease_ttl" structs:"max_lease_ttl" mapstructure:"max_lease_ttl"`
}

type policies struct {
	Name  string `hcl:"name,ommitempty"`
	Rules string `hcl:"rules,ommitempty"`
}

type auth struct {
	Type        string `hcl:"type,ommitempty"`
	Description string `hcl:"description,ommitempty"`
	Users       []struct {
		Name    string                 `hcl:"name,ommitempty"`
		Options map[string]interface{} `hcl:"options,ommitempty"`
	} `hcl:"users,ommitempty"`
	Groups []struct {
		Name    string                 `hcl:"name,ommitempty"`
		Options map[string]interface{} `hcl:"options,ommitempty"`
	} `hcl:"groups,ommitempty"`
	MountConfig mountConfigInput       `hcl:"mountconfig,ommitempty"`
	AuthConfig  map[string]interface{} `hcl:"authconfig,ommitempty"`
}

// NewClient returns a Vault client
func NewClient(c *api.Config) (*VCClient, error) {
	client, err := api.NewClient(c)
	if err != nil {
		return nil, err
	}

	return &VCClient{client}, nil
}
