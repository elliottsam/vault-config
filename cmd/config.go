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
	"io/ioutil"
	"log"

	"fmt"

	"github.com/elliottsam/vault-config/crypto"
	"github.com/elliottsam/vault-config/vault"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
)

// configCmd configures Vault server with configuration provided
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Executes configuration of Vault",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		file, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Fatal("Error reading file: ", err)
		}

		e := crypto.EncryptionObject{}
		if encrypted {
			if key == "" {
				log.Fatal("Error no encryption key entered")
			}
			e.Key = key
			e.WrappedData = string(file)
			if err := e.UnwrapCrypto(); err != nil {
				log.Fatal(err)
			}
			if err := e.Decrypt(); err != nil {
				log.Fatal(err)
			}
		} else {
			e.PlainText = file
		}

		config := api.DefaultConfig()
		client, err := vault.NewClient(config)
		if err != nil {
			log.Fatalf("Error creating Vault client: %v", err)

		}

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
			if !client.PolicyExist(p.Name) {
				if err := client.PolicyAdd(p); err != nil {
					log.Fatal(err)
				}
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
			if err := client.WriteTokenRole(v.Name, vault.ConvertMapStringInterface(v.Options)); err != nil {
				log.Fatal("Error writing token role: %v", err)
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(configCmd)

	configCmd.Flags().StringVarP(&filename, "filename", "f", "config.hcl", "Filename of configuration file")
	configCmd.Flags().BoolVarP(&encrypted, "encrypted", "e", false, "Is this file encrypted")
	configCmd.Flags().StringVarP(&key, "key", "k", "", "Encryption key this must be 32 bytes")
}
