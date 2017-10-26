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

	"github.com/elliottsam/github"
	"github.com/elliottsam/vault-config/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	filename          string
	varFile           string
	encrypted         bool
	key               string
	input             string
	output            string
	deleteFile        bool
	vcVaultAddr       string
	vcVaultToken      string
	vcVaultSkipVerify bool
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "vault-config",
	Short: "vault-config is a tool for codifying the configuration of vault",
	Long: `vault-config is a tool for codifying the configuration of vault
configuration is defined in HCL and it utilises encryption so
sensitive data can be pushed to github or similar

To configure a Vault server you need to specify the following
environment variables

VC_VAULT_ADDR        - Address of Vault server to apply config to
VC_VAULT_TOKEN       - Token to authenticate to Vault with
VC_VAULT_SKIP_VERIFY - Skip TLS verification

The standard Vault environment variables can be configured for
use with the templating engine, this will allow getting secrets
from another Vault server, see the README for more information`,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		RootCmd.Help()
	}
}

func init() {
	err := github.IsLatestRelease("elliottsam", "vault-config", version.Version)
	if err != nil {
		fmt.Println(err)
	}
	viper.AutomaticEnv()
	viper.SetEnvPrefix("vc")
	vcVaultAddr = viper.GetString("vault_addr")
	vcVaultToken = viper.GetString("vault_token")
}
