// Copyright © 2017 Sam Elliott <me@sam-e.co.uk>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"log"

	"encoding/base64"

	"github.com/elliottsam/vault-config/crypto"
	"github.com/elliottsam/vault-config/template"
	"github.com/elliottsam/vault-config/vault"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
)

// configCmd configures Vault server with configuration provided
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Executes configuration of Vault",
	Long: `vault-config configure will read through all
configuration files with the .vc extension and
apply changes to Vault

Vault configuration is retrieved through the
same environment variables the main Vault
client uses

If the -encrypted flag is set, the tool will
also cycle through all .vc.enc files and decrypt
these a key will be requested if not passed
via the -key flag

e.g.
vault-config config -e -k mSskqBC85rA65lofPOaQcVtjjnHJ16rI+/rqZfkBwqs=

This will cycle through all .vc and .vc.enc files
decrypting those that require it
`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		e := crypto.EncryptionObject{}
		e.PlainText = e.ReadConfigFiles(filename)
		if encrypted {
			if key == "" {
				e.Key, err = crypto.GetPassword()
				if err != nil {
					log.Fatal(err)
				}
			} else {
				e.Key, err = base64.StdEncoding.DecodeString(key)
				if err != nil {
					log.Fatalf("Error base64 decoding key: %v", err)
				}
			}
			e.PlainText = crypto.JoinBytes(e.ReadEncryptedConfigFiles(filename), e.PlainText)
		}

		g := template.InitGenerator(varFile, e.PlainText)
		e.PlainText, err = g.GenerateConfig()
		if err != nil {
			log.Fatalf("Error generating config from template: %v", err)
		}

		c := api.DefaultConfig()
		c.Address = vcVaultAddr
		if vcVaultSkipVerify == true {
			c.ConfigureTLS(&api.TLSConfig{Insecure: true})
		}
		client, err := vault.NewClient(c)
		if err != nil {
			log.Fatalf("Error creating Vault client: %v", err)

		}
		client.SetToken(vcVaultToken)

		var vconf vault.Config
		err = hcl.Unmarshal(e.PlainText, &vconf)
		if err != nil {
			log.Fatal(fmt.Errorf("Error reading HCL: %v", err))
		}
		for _, m := range vconf.Mounts {
			if ok := client.MountExist(m.Path); !ok {
				err := client.Mount(m.Path, vault.ConvertMapStringInterface(m.Config))
				if err != nil {
					log.Fatalf("Error creating mount: %v", err)
				}
			}
			if err := client.TuneMount(m.Path, vault.ConvertMapStringInterface(m.Config.MountConfig)); err != nil {
				log.Fatal(err)
			}
		}

		for _, p := range vconf.Policies {
			if err := client.PolicyAdd(p); err != nil {
				log.Fatal(err)
			}
		}

		if vconf.Auth.Ldap != nil {
			if err := vault.EnableAndConfigure(vconf.Auth.Ldap, client); err != nil {
				log.Fatal(fmt.Errorf("Error creating Ldap auth:\n%s", err))
			}
		}

		if vconf.Auth.Github != nil {
			if err := vault.EnableAndConfigure(vconf.Auth.Github, client); err != nil {
				log.Fatal(fmt.Errorf("Error creating Github auth:\n%s", err))
			}
		}

		for _, v := range vconf.TokenRoles {
			if err := client.WriteTokenRole(v); err != nil {
				log.Fatal("Error writing token role: %v", err)
			}
		}

		for _, v := range vconf.Secrets {
			if err := client.WriteSecret(v); err != nil {
				log.Fatalf("Error: %v", err)
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(configCmd)

	configCmd.Flags().StringVarP(&filename, "filename", "f", "", "Filename of configuration file")
	configCmd.Flags().StringVarP(&varFile, "varFile", "v", "vault-config.vars", "Filename of vars to be used in templates")
	configCmd.Flags().BoolVarP(&encrypted, "encrypted", "e", false, "Is this file encrypted")
	configCmd.Flags().StringVarP(&key, "key", "k", "", "Encryption key this must be 32 bytes")
}
