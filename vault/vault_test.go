package vault

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/stretchr/testify/assert"
)

func (vsc *vaultServerConfigTestSuite) testAuthBackendEnable(a AuthType) {
	assert.False(vsc.T(), vsc.vtc.AuthExist(a.GetType()))
	err := vsc.vtc.AuthEnable(a)
	assert.NoError(vsc.T(), err, "AuthEnable should not return an error: ", err)
	assert.True(vsc.T(), vsc.vtc.AuthExist(a.GetType()), "AuthExist should return true after enabling auth type: ", a.GetType())
}

func (vsc *vaultServerConfigTestSuite) testAuthBackendConfiguration(a AuthType) {
	vsc.vtc.AuthConfigure(a)
	s, err := vsc.vtc.Logical().Read("auth/" + a.GetType() + "/config")
	assert.NoError(vsc.T(), err, "Should not error reading Auth config path: ", err)
	ac := a.getAuthConfig()
	for k, _ := range ac {
		assert.Equal(vsc.T(), ac[k], s.Data[k], fmt.Sprintf("Local config should match Vault server for key: %v"), k)
	}
}

func (vsc *vaultServerConfigTestSuite) testAuthBackendMountConfiguration(a AuthType) {
	mc := a.getAuthMountConfig()
	vsc.vtc.TuneMount(Path(a), mc)
	s, err := vsc.vtc.Client.Logical().Read("sys/" + Path(a) + "/tune")
	assert.NoError(vsc.T(), err, "Should not error reading Auth config path: ", err)
	edttl, _ := time.ParseDuration(mc["default_lease_ttl"].(string))
	adttl, _ := time.ParseDuration(fmt.Sprintf("%ss", s.Data["default_lease_ttl"]))
	assert.Equal(vsc.T(), edttl, adttl, "DefaultLeaseTTL should match")
	emttl, _ := time.ParseDuration(mc["max_lease_ttl"].(string))
	amttl, _ := time.ParseDuration(fmt.Sprintf("%ss", s.Data["max_lease_ttl"]))
	assert.Equal(vsc.T(), emttl, amttl, "MaxLeaseTTL should match")
}

func (vsc *vaultServerConfigTestSuite) TestVCClient_Auth() {
	// Testing enabling an Auth backends
	vsc.testAuthBackendEnable(vc.Auth.Ldap)
	//vsc.testAuthBackendEnable(vc.Auth.Github)

	// Testing configuring Auth backend
	vsc.testAuthBackendConfiguration(vc.Auth.Ldap)
	//vsc.testAuthBackendConfiguration(vc.Auth.Github)

	// Test auth mount tuning has worked as expected
	vsc.testAuthBackendMountConfiguration(vc.Auth.Ldap)
	//vsc.testAuthBackendMountConfiguration(vc.Auth.Github)
}

func (vsc *vaultServerConfigTestSuite) TestVCClient_Mounts() {
	// Test creating new mounts from config
	for _, v := range vc.Mounts {
		assert.False(vsc.T(), vsc.vtc.MountExist(v.Path), "Mount should not exist at beginning of test: ", v.Path)
		err := vsc.vtc.Mount(v.Path, ConvertMapStringInterface(v.Config))
		assert.NoError(vsc.T(), err, "Creating mount should not cause an error: ", err)
		assert.True(vsc.T(), vsc.vtc.MountExist(v.Path), "Mount should exist after creation: ", v.Path)
	}

	// Test that custom mount configuration has been completed successfully
	mount := vc.Mounts[0]
	mts, err := vsc.vtc.Logical().Read("sys/mounts")
	mt, ok := mts.Data[fmt.Sprintf("%s/", mount.Path)].(map[string]interface{})["config"].(map[string]interface{})
	if ok {
		assert.NoError(vsc.T(), err, "No error should occur whilst reading Vault configuration")
		edttl, _ := time.ParseDuration(mount.Config.MountConfig.DefaultLeaseTTL)
		adttl, _ := time.ParseDuration(fmt.Sprintf("%ss", mt["default_lease_ttl"].(json.Number)))
		assert.Equal(vsc.T(), edttl, adttl, "dttl should be whilst reading Vault configuration")
		emttl, _ := time.ParseDuration(mount.Config.MountConfig.MaxLeaseTTL)
		amttl, _ := time.ParseDuration(fmt.Sprintf("%ss", mt["max_lease_ttl"].(json.Number)))
		assert.Equal(vsc.T(), emttl, amttl, "mttl should be equal to value from configuration")
	} else {
		vsc.T().Errorf("No mount found: %v")
	}
}

func (vcs *vaultServerConfigTestSuite) TestVCClient_Policy() {
	for _, v := range vc.Policies {
		assert.False(vcs.T(), vcs.vtc.PolicyExist(v.Name), "Policy should not exist before add:", v.Name)
		err := vcs.vtc.PolicyAdd(v)
		assert.NoError(vcs.T(), err, "Adding new policy with valid data should return no error:", v.Name)
		assert.True(vcs.T(), vcs.vtc.PolicyExist(v.Name), "Policy should exist after add:", v.Name)
		pol, err := vcs.vtc.Sys().GetPolicy(v.Name)
		assert.NoError(vcs.T(), err, "Getting policy should return no error:", err)
		assert.Equal(vcs.T(), v.Rules, pol, "Policy should match input configuration")
	}
}
