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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"github.com/elliottsam/vault-config/crypto"
	"github.com/elliottsam/vault-config/template"
	"github.com/elliottsam/vault-config/vault"
	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
)

var (
	path       string
	generate   bool
	decodedKey []byte
)

const secret_tmpl = `
{{ range . }}
{{ LookupSecret . }}
{{ end }}
`

var e crypto.EncryptionObject

// exportCmd represents the export command
var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export walks a path and exports secrets",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if path == "" {
			log.Fatal("Please supply a Vault path with the -path parameter")
		}

		c := api.DefaultConfig()
		if tlsSkipVerify, ok := os.LookupEnv("VAULT_SKIP_VERIFY"); ok {
			if tlsSVBool, err := strconv.ParseBool(tlsSkipVerify); err != nil {
				log.Fatal("Error parsing VAULT_SKIP_VERIFY boolean")
			} else {
				c.ConfigureTLS(&api.TLSConfig{Insecure: tlsSVBool})
			}
		}
		client, err := vault.NewClient(c)
		if err != nil {
			log.Fatal("Error creating Vault client")
		}

		sPath, err := client.WalkVault(path)
		if err != nil {
			log.Fatal(err)
		}

		tmpl := template.InitGenerator("", []byte(secret_tmpl))
		for _, v := range sPath {
			tmpl.UpdateVarsMap(v, v)
		}
		e.PlainText = tmpl.GenerateConfig()

		if encrypted {

			if generate {
				decodedKey = crypto.RandomKey(32)
				log.Printf("Generated Key: %s\n", base64.StdEncoding.EncodeToString(decodedKey))
			} else if key == "" {
				log.Fatalf("Error: No encryption key supplied, either provide key or generate")
			} else {
				decodedKey, err = base64.StdEncoding.DecodeString(key)
				if err != nil {
					log.Fatalf("Error decoding base64 key: %v", key)
				}
			}

			err = e.InlineEncryptMap("secret/data")
			if err != nil {
				log.Fatalf("Error encrypting Vault Config: %v", err)
			}
			e.PlainText = e.CipherText
		}

		e.PlainText, err = printer.Format(e.PlainText)
		if err != nil {
			log.Fatalf("Error formatting vault-config: %v", err)
		}

		if output == "" {
			fmt.Println(string(e.PlainText))
		} else {
			if err := ioutil.WriteFile(output, e.PlainText, 0600); err != nil {
				log.Fatalf("Error writing vault config to file: %v", err)
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(exportCmd)

	exportCmd.Flags().StringVarP(&path, "path", "p", "", "Path to retrieve secrets from")
	exportCmd.Flags().BoolVarP(&encrypted, "encrypted", "e", false, "Should output be encrypted?")
	exportCmd.Flags().StringVarP(&key, "key", "k", "", "Encryption key this must be 32 bytes")
	exportCmd.Flags().BoolVarP(&generate, "generate", "g", false, "Generate encyption key at runtime")
	exportCmd.Flags().StringVarP(&output, "output", "o", "", "Filename to output configuration to")
}
