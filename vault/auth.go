package vault

import (
	"fmt"
	"log"
	"strings"
)

// AuthExist checks for the existance of an Auth mount
func (c *VCClient) AuthExist(name string) bool {
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

func (a *auth) path() string {
	return fmt.Sprintf("auth/%s", a.Type)
}

// AuthEnable enables an auth backend
func (c *VCClient) AuthEnable(a auth) error {
	if err := c.Sys().EnableAuth(a.Type, a.Type, a.Description); err != nil {
		return err
	}

	return nil
}

// AuthConfigure sets the configuration for an auth backend
func (c *VCClient) AuthConfigure(auth auth) error {
	confpath := fmt.Sprintf("%s/config", auth.path())
	_, err := c.Logical().Write(confpath, auth.AuthConfig)
	if err != nil {
		return fmt.Errorf("Error writing auth config to mount: %v", err)
	}
	for _, v := range auth.Users {
		path := fmt.Sprintf("%s/users/%s", auth.path(), v.Name)
		_, err := c.Logical().Write(path, v.Options)
		if err != nil {
			log.Fatal(err)
		}
	}

	c.TuneMount(auth.path(), auth.MountConfig)

	return nil
}
