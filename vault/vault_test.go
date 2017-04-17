package vault

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/stretchr/testify/assert"
)

func (vsc *vaultServerConfigTestSuite) TestVCClient_Auth() {
	// Testing enabling an Auth backend
	for _, v := range vc.Auth {
		assert.False(vsc.T(), vsc.vtc.AuthExist(v.Type))
		err := vsc.vtc.AuthEnable(v)
		assert.NoError(vsc.T(), err, "AuthEnable should not return an error: ", err)
		assert.True(vsc.T(), vsc.vtc.AuthExist(v.Type), "AuthExist should return true after enabling auth type: ", v.Type)
	}

	// Testing configuring Auth backend
	for _, v := range vc.Auth {
		vsc.vtc.AuthConfigure(v)
		s, err := vsc.vtc.Logical().Read("auth/" + v.Type + "/config")
		assert.NoError(vsc.T(), err, "Should not error reading Auth config path: ", err)
		for k, _ := range v.AuthConfig {
			assert.Equal(vsc.T(), v.AuthConfig[k], s.Data[k], fmt.Sprintf("Local config should match Vault server for key: %v"), k)
		}
	}

	// Test auth mount tuning has worked as expected
	for _, v := range vc.Auth {
		vsc.vtc.TuneMount(v.path(), v.MountConfig)
		s, err := vsc.vtc.Client.Logical().Read("sys/" + v.path() + "/tune")
		assert.NoError(vsc.T(), err, "Should not error reading Auth config path: ", err)
		edttl, _ := time.ParseDuration(v.MountConfig.DefaultLeaseTTL)
		adttl, _ := time.ParseDuration(fmt.Sprintf("%ss", s.Data["default_lease_ttl"]))
		assert.Equal(vsc.T(), edttl, adttl, "DefaultLeaseTTL should match")
		emttl, _ := time.ParseDuration(v.MountConfig.MaxLeaseTTL)
		amttl, _ := time.ParseDuration(fmt.Sprintf("%ss", s.Data["max_lease_ttl"]))
		assert.Equal(vsc.T(), emttl, amttl, "MaxLeaseTTL should match")
	}
}

func (vsc *vaultServerConfigTestSuite) TestVCClient_Mounts() {
	// Test creating new mounts from config
	for _, v := range vc.Mount {
		assert.False(vsc.T(), vsc.vtc.MountExist(v.Path), "Mount should not exist at beginning of test: ", v.Path)
		err := vsc.vtc.Mount(v.Path, v.Config)
		assert.NoError(vsc.T(), err, "Creating mount should not cause an error: ", err)
		assert.True(vsc.T(), vsc.vtc.MountExist(v.Path), "Mount should exist after creation: ", v.Path)
	}

	// Test that custom mount configuration has been completed successfully
	mount := vc.Mount[0]
	mts, err := vsc.vtc.Logical().Read("sys/mounts")
	mt, ok := mts.Data[fmt.Sprintf("%s/", mount.Path)].(map[string]interface{})["config"].(map[string]interface{})
	if ok {
		assert.NoError(vsc.T(), err, "No error should occur whilst reading Vault configuration")
		edttl, _ := time.ParseDuration(mount.Config.Config.DefaultLeaseTTL)
		adttl, _ := time.ParseDuration(fmt.Sprintf("%ss", mt["default_lease_ttl"].(json.Number)))
		assert.Equal(vsc.T(), edttl, adttl, "dttl should be whilst reading Vault configuration")
		emttl, _ := time.ParseDuration(mount.Config.Config.MaxLeaseTTL)
		amttl, _ := time.ParseDuration(fmt.Sprintf("%ss", mt["max_lease_ttl"].(json.Number)))
		assert.Equal(vsc.T(), emttl, amttl, "mttl should be equal to value from configuration")
	} else {
		vsc.T().Errorf("No mount found: %v")
	}
}

func (vcs *vaultServerConfigTestSuite) TestVCClient_Policy() {
	for _, v := range vc.Policy {
		assert.False(vcs.T(), vcs.vtc.PolicyExist(v.Name), "Policy should not exist before add:", v.Name)
		err := vcs.vtc.PolicyAdd(v)
		assert.NoError(vcs.T(), err, "Adding new policy with valid data should return no error:", v.Name)
		assert.True(vcs.T(), vcs.vtc.PolicyExist(v.Name), "Policy should exist after add:", v.Name)
		pol, err := vcs.vtc.Sys().GetPolicy(v.Name)
		assert.NoError(vcs.T(), err, "Getting policy should return no error:", err)
		assert.Equal(vcs.T(), v.Rules, pol, "Policy should mattch input configuration")
	}
}
