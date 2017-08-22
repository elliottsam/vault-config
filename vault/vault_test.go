package vault

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/stretchr/testify/assert"
)

func (vsc *vaultServerConfigTestSuite) testAuthBackendEnable(a AuthType) {
	assert.False(vsc.T(), vsc.vtc.AuthExist(a.GetType()), "Auth should not exist before enable: %s", a.GetType())
	err := vsc.vtc.AuthEnable(a)
	assert.NoError(vsc.T(), err, "AuthEnable should not return an error: %v", err)
	assert.True(vsc.T(), vsc.vtc.AuthExist(a.GetType()), "AuthExist should return true after enabling auth type: %s", a.GetType())
}

func (vsc *vaultServerConfigTestSuite) testAuthBackendConfiguration(a AuthType) {
	vsc.vtc.AuthConfigure(a)
	s, err := vsc.vtc.Logical().Read("auth/" + a.GetType() + "/config")
	assert.NoError(vsc.T(), err, "Should not error reading Auth config path: %v", err)
	ac := a.getAuthConfig()
	for k, _ := range ac {
		assert.Equal(vsc.T(), ac[k], s.Data[k], "Local config should match Vault server for key: %v", k)
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

func (vsc *vaultServerConfigTestSuite) TestVCClient_MountsAndSecrets() {
	// Test creating new mounts from config
	for _, v := range vc.Mounts {
		assert.False(vsc.T(), vsc.vtc.MountExist(v.Path), "Mount should not exist at beginning of test: %s", v.Path)
		err := vsc.vtc.Mount(v.Path, ConvertMapStringInterface(v.Config))
		assert.NoError(vsc.T(), err, "Creating mount should not cause an error: %v", err)
		assert.True(vsc.T(), vsc.vtc.MountExist(v.Path), "Mount should exist after creation: %s", v.Path)
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
		vsc.T().Errorf("No mount found: %v", mount.Path)
	}

	// Test adding secrets to the vault server
	for _, v := range vc.Secrets {
		assert.False(vsc.T(), vsc.vtc.secretExist(v), "Secret should not exist before write: %s", v.Name)
		err := vsc.vtc.WriteSecret(v)
		assert.NoError(vsc.T(), err, "Writing secret should not return an error: %s", v.Name)
		assert.True(vsc.T(), vsc.vtc.secretExist(v), "Secret should exist after write: %s", v.Name)
		secret, err := vsc.vtc.Logical().Read(v.Path)
		assert.NoError(vsc.T(), err, "Reading secret path should not return an error: %s", v.Name)
		assert.Equal(vsc.T(), v.Data, secret.Data, "Secret should match input: %s", v.Name)
	}

	// Test walking vault secret mount
	vwo, err := vsc.vtc.WalkVault("example/app1")
	assert.NoError(vsc.T(), err, "Walking Vault should not generate any errors")
	assert.Equal(vsc.T(), 3, len(vwo), "Walk should return 3 paths")
}

func (vsc *vaultServerConfigTestSuite) TestVCClient_Policy() {
	for _, v := range vc.Policies {
		assert.False(vsc.T(), vsc.vtc.PolicyExist(v.Name), "Policy should not exist before add: %s", v.Name)
		err := vsc.vtc.PolicyAdd(v)
		assert.NoError(vsc.T(), err, "Adding new policy with valid data should return no error: %s", v.Name)
		assert.True(vsc.T(), vsc.vtc.PolicyExist(v.Name), "Policy should exist after add: %s", v.Name)
		pol, err := vsc.vtc.Sys().GetPolicy(v.Name)
		assert.NoError(vsc.T(), err, "Getting policy should return no error: %v", err)
		assert.Equal(vsc.T(), v.Rules, pol, "Policy should match input configuration")
	}

	// Check that policies update with new details
	for _, v := range pUpdate.Policies {
		pol, err := vsc.vtc.Sys().GetPolicy(v.Name)
		assert.NoError(vsc.T(), err, "Getting policy should return no error: %v", err)
		assert.NotEqual(vsc.T(), v.Rules, pol, "Policy should not match input configuration")
		err = vsc.vtc.PolicyAdd(v)
		assert.NoError(vsc.T(), err, "Updating policy with valid data should return no error: %s", v.Name)
		pol, err = vsc.vtc.Sys().GetPolicy(v.Name)
		assert.NoError(vsc.T(), err, "Getting policy should return no error: %v", err)
		assert.Equal(vsc.T(), v.Rules, pol, "Policy should match input configuration")
	}
}

func (vsc *vaultServerConfigTestSuite) TestVCClient_TokenRole() {
	for _, v := range vc.TokenRoles {
		assert.False(vsc.T(), vsc.vtc.tokenRoleExists(v), "Token role should not exist before add: %s", v.Name)
		err := vsc.vtc.WriteTokenRole(v)
		assert.NoError(vsc.T(), err, "Adding new token role should return no error:", v.Name)
		assert.True(vsc.T(), vsc.vtc.tokenRoleExists(v), "Token role should exist after add: %s", v.Name)
		path := fmt.Sprintf("auth/token/roles/%s", v.Name)
		_, err = vsc.vtc.Logical().Read(path)
		assert.NoError(vsc.T(), err, "Reading token role should return no error: %v", err)
		//assert.Equal(vsc.T(), v.Options, tr.Data, "Policy should match input configuration")
	}
}
