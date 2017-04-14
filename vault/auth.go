package vault

import (
	"fmt"
	"log"
	"strings"
)

func (c *VaultClient) AuthExist(name string) bool {
	auth, err := c.Sys().ListAuth()
	if err != nil {
		return false
	}
	for a := range auth {
		if strings.TrimSuffix(a, "/") == name {
			return true
		}
	}

	return false
}

func (a *auth) Path() string {
	return fmt.Sprintf("auth/%s", a.Type)
}

func (c *VaultClient) AuthEnable(a auth) error {
	if err := c.Sys().EnableAuth(a.Type, a.Type, a.Description); err != nil {
		return err
	}

	return nil
}

func (c *VaultClient) AuthConfigure(auth auth) error {
	confpath := fmt.Sprintf("%s/config", auth.Path())
	_, err := c.Logical().Write(confpath, auth.AuthConfig)
	if err != nil {
		return fmt.Errorf("Error writing auth config to mount: %v", err)
	}
	for _, v := range auth.Users {
		path := fmt.Sprintf("%s/users/%s", auth.Path(), v.Name)
		_, err := c.Logical().Write(path, v.Options)
		if err != nil {
			log.Fatal(err)
		}
	}

	c.TuneMount(auth.Path(), auth.MountConfig)

	return nil
}
