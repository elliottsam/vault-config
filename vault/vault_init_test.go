package vault

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/suite"
)

type vaultServerConfigTestSuite struct {
	suite.Suite
	vaultToken   string
	vaultAddress string
	vaultCmd     string
	proc         *os.Process
	vtc          *VCClient
}

var vc Config
var pUpdate Config

func (v *vaultServerConfigTestSuite) SetupSuite() {
	// TODO Make tests work on Windows as well as Linux
	vaultCmd := `vault`
	vaultCmd, err := exec.LookPath(vaultCmd)
	if err != nil {
		log.Fatalf("Vault not found on PATH: %v", err)
	}
	v.vaultToken = "root"
	v.vaultAddress = "http://127.0.0.1:8200"
	v.vaultCmd = vaultCmd

	initVaultServer(v)
	td, _ := time.ParseDuration("1s")
	time.Sleep(td)
	v.initVaultTestClient()
	time.Sleep(td)
	if err := hcl.Decode(&vc, hcl_config); err != nil {
		v.T().Fatalf("Error decoding HCL: %v", err)
	}
	if err := hcl.Decode(&pUpdate, policyUpdate); err != nil {
		v.T().Fatalf("Error decoding HCL: %v", err)
	}
}

func (v *vaultServerConfigTestSuite) TearDownSuite() {
	v.killVaultServer()
}

func initVaultServer(v *vaultServerConfigTestSuite) {
	cmd := exec.Command(v.vaultCmd,
		"server",
		"-dev",
		fmt.Sprintf("-dev-root-token-id=%s", v.vaultToken),
		fmt.Sprintf("-dev-listen-address=%s", strings.TrimPrefix(v.vaultAddress, "http://")),
	)
	if err := cmd.Start(); err != nil {
		v.T().Fatalf("Error starting Vault server: %v", err)
	}
	v.proc = cmd.Process
}

func (v *vaultServerConfigTestSuite) killVaultServer() {
	if err := v.proc.Kill(); err != nil {
		v.T().Fatalf("Error killing Vault process: %v\nProcess ID:%d", err, v.proc.Pid)
	}
}

func (v *vaultServerConfigTestSuite) initVaultTestClient() {
	conf := api.DefaultConfig()
	conf.Address = v.vaultAddress
	c, err := api.NewClient(conf)
	if err != nil {
		v.T().Fatalf("Error creating Vault client: %v", err)
	}
	c.SetToken(v.vaultToken)

	v.vtc = &VCClient{c}
}

func TestVaultServerConfigTestSuite(t *testing.T) {
	suite.Run(t, new(vaultServerConfigTestSuite))
}

const hcl_config = `mount "app1" {
  path = "example/app1"
  config {
    type = "generic"
    description = "Example App 1"
  }
  mountconfig {
    default_lease_ttl = "20h"
    max_lease_ttl = "768h"
  }
}

mount "pki" {
  path = "pki"
  config {
    type = "pki"
    description = "My cool PKI backend"
  }
  mountconfig {
    default_lease_ttl = "768h"
    max_lease_ttl = "768h"
  }
}

mount "app2" {
  path = "example/app2"
  config {
    type = "generic"
    description = "Example App 2"
  }
  mountconfig {
    default_lease_ttl = "1h"
    max_lease_ttl = "24h"
  }
}


policy "example-policy-1" {
  rules =<<EOF
# Allow to make changes to /example/app1 mount
path "example/app1" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
EOF
}

policy "example-policy-2" {
  rules =<<EOF
# Allow to make changes to /example/app2 mount
path "example/app2" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
EOF
}

token_role "example_period_token_role" {
  options {
    allowed_policies = "example-policy-1,example-policy-2"
    period = 20
    renewable = true
  }
}

auth {
  ldap {
    description = "LDAP Auth backend config"
    authconfig {
      binddn = "CN=SamE,CN=Users,DC=test,DC=local"
      bindpass = "z"
      url = "ldap://10.255.0.30"
      userdn = "CN=Users,DC=test,DC=local"
    }
    group "groupa" {
      options {
        policies = "example-policy-1"
      }
    }
    user "same" {
      options {
        policies = "example-policy-1,example-policy-2"
      }
    }
    mountconfig {
      default_lease_ttl = "1h"
      max_lease_ttl = "24h"
    }
  }
  github {
    authconfig = {
      organization = "testorg"
    }
  }
}

secret "test" {
	path = "/example/app1/test"
	data {
		value = "test1"
		password = "test2"
	}
}`

const policyUpdate = `
policy "example-policy-1" {
  rules =<<EOF
# Allow to make changes to /example/app1 mount
path "example/app1" {
    capabilities = ["read", "list"]
}
EOF
}

policy "example-policy-2" {
  rules =<<EOF
# Allow to make changes to /example/app2 mount
path "example/app2" {
    capabilities = ["read", "list"]
}
EOF
}`
