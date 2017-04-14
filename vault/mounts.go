package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/fatih/structs"
)

func (c *VaultClient) MountExist(name string) bool {
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

func (c *VaultClient) Mount(path string, mountInfo *MountInput) error {
	body := structs.Map(mountInfo)

	r := c.NewRequest("POST", fmt.Sprintf("/v1/sys/mounts/%s", path))
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

func (c *VaultClient) TuneMount(path string, config MountConfigInput) error {
	body := structs.Map(config)
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
