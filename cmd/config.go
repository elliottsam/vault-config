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

		var vconf vault.VaultConfig
		err = hcl.Unmarshal(e.PlainText, &vconf)
		if err != nil {
			log.Fatalf("Error reading HCL: %v", err)
		}

		for _, m := range vconf.Mount {
			if ok := client.MountExist(m.Path); !ok {
				err := client.Mount(m.Path, m.Config)
				if err != nil {
					log.Fatalf("Error creating mount: %v", err)
				}
			}
			if err := client.TuneMount(m.Path, m.Config.Config); err != nil {
				log.Fatal(err)
			}
		}

		for _, p := range vconf.Policy {
			if !client.PolicyExist(p.Name) {
				client.PolicyAdd(p)
			}
		}

		for _, a := range vconf.Auth {
			if !client.AuthExist(a.Type) {
				err := client.AuthEnable(a)
				if err != nil {
					log.Fatalf("Error enabling auth mount: %v", err)
				}
			}
			client.AuthConfigure(a)
		}
	},
}

func init() {
	RootCmd.AddCommand(configCmd)

	configCmd.Flags().StringVarP(&filename, "filename", "f", "config.hcl", "Filename of configuration file")
	configCmd.Flags().BoolVarP(&encrypted, "encrypted", "e", false, "Is this file encrypted")
	configCmd.Flags().StringVarP(&key, "key", "k", "", "Encryption key this must be 32 bytes")
}
