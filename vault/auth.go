package vault

import (
	"fmt"
	"strings"
)

// AuthType defines an interface for dealing with Auth backends
type AuthType interface {
	Describe() string
	GetType() string
	getAuthConfig() map[string]interface{}
	getAuthMountConfig() map[string]interface{}
	//AConfig() map[string]interface{}
	Configure(c *VCClient) error
	TuneMount(c *VCClient, path string) error
	WriteUsers(c *VCClient) error
	WriteGroups(c *VCClient) error
}

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

// Path will return the path of an Auth backend
func Path(a AuthType) string {
	return fmt.Sprintf("auth/%s", a.GetType())
}

// AuthEnable enables an auth backend
func (c *VCClient) AuthEnable(a AuthType) error {
	if err := c.Sys().EnableAuth(a.GetType(), a.GetType(), a.Describe()); err != nil {
		return err
	}

	return nil
}

// AuthConfigure sets the configuration for an auth backend
func (c *VCClient) AuthConfigure(a AuthType) error {
	if err := a.WriteUsers(c); err != nil {
		return err
	}
	if err := a.WriteGroups(c); err != nil {
		return err
	}
	if err := a.TuneMount(c, Path(a)); err != nil {
		return err
	}

	if err := a.Configure(c); err != nil {
		return err
	}

	return nil
}

func EnableAndConfigure(a AuthType, c *VCClient) error {
	if !c.AuthExist(a.GetType()) {
		if err := c.AuthEnable(a); err != nil {
			return fmt.Errorf("Error enabling auth mount: %v", err)
		}
	}
	if err := c.AuthConfigure(a); err != nil {
		return fmt.Errorf("Error configuring auth mount: %v", err)
	}

	return nil
}
