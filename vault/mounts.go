package vault

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

// MountExist checks for the existence of specified mount
func (c *VCClient) MountExist(name string) bool {
	if !strings.HasSuffix(name, "/") {
		name = fmt.Sprintf("%s/", name)
	}
	name = strings.TrimPrefix(name, "/")

	mounts, err := c.Sys().ListMounts()
	if err != nil {
		log.Fatal(err)
	}
	var ok bool
	if _, ok = mounts[name]; !ok {
		return false
	}

	return true
}

// Mount creates a new mount on Vault server
func (c *VCClient) Mount(path string, config map[string]interface{}) error {
	body := config

	r := c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/mounts/%s", path))
	if err := r.SetJSONBody(body); err != nil {
		return err
	}

	resp, err := c.RawRequest(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// TuneMount will configure a mounts settings
func (c *VCClient) TuneMount(path string, config map[string]interface{}) error {
	body := config
	r := c.NewRequest("POST", fmt.Sprintf("/v1/sys/mounts/%s/tune", path))
	if err := r.SetJSONBody(body); err != nil {
		return err
	}

	resp, err := c.RawRequest(r)
	if err == nil {
		defer resp.Body.Close()
	}
	return err
}
