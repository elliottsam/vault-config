package vault

import "github.com/hashicorp/vault/api"

type VaultClient struct {
	*api.Client
}

type VaultConfig struct {
	Mount  []mounts   `hcl:"mounts,ommitempty"`
	Policy []policies `hcl:"policies,ommitempty"`
	Auth   []auth     `hcl:"auth,ommitempty"`
}

type mounts struct {
	Path   string      `hcl:"path,ommitempty"`
	Config *MountInput `hcl:"config,ommitempty"`
}

type MountInput struct {
	Type        string           `hcl:"type" structs:"type"`
	Description string           `hcl:"description" structs:"description"`
	Config      MountConfigInput `hcl:"mountconfig" structs:"config"`
}

type MountConfigInput struct {
	DefaultLeaseTTL string `hcl:"default_lease_ttl" structs:"default_lease_ttl" mapstructure:"default_lease_ttl"`
	MaxLeaseTTL     string `hcl:"max_lease_ttl" structs:"max_lease_ttl" mapstructure:"max_lease_ttl"`
}

type policies struct {
	Name  string `hcl:"name,ommitempty"`
	Rules string `hcl:"rules,ommitempty"`
}

type auth struct {
	//Path        string                 `hcl:"path,ommitempty"`
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
	MountConfig MountConfigInput       `hcl:"mountconfig,ommitempty"`
	AuthConfig  map[string]interface{} `hcl:"authconfig,ommitempty"`
}

func NewClient(c *api.Config) (*VaultClient, error) {
	client, err := api.NewClient(c)
	if err != nil {
		return nil, err
	}

	return &VaultClient{client}, nil
}
