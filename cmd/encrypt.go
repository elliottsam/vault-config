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
	"io/ioutil"
	"log"
	"os"

	"fmt"

	"github.com/elliottsam/vault-config/crypto"
	"github.com/spf13/cobra"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypts a file using the specified key",
	Long: `Encrypts a file using the specified key, if the
delete flag is set to true, this will also delete
the original file

The key specified needs to be 32 bytes long and
base 64 encoded, this can be generated with the
keygen command

If the key is not specified it will be requested
from the command line

i.e.
vault-config encrypt -i config.vc -k mSskqBC85rA65lofPOaQcVtjjnHJ16rI+/rqZfkBwqs=

Will encrypt the file 'config.vc' to 'config.vc.enc'`,
	Run: func(cmd *cobra.Command, args []string) {
		if input == "" {
			log.Fatalf("No input file specified, use paramter -input")
		}
		var err error
		e := crypto.EncryptionObject{}
		if key == "" {
			e.Key, err = crypto.GetPassword()
			if err != nil {
				log.Fatal(err)
			}
		} else {
			e.Key, err = base64.StdEncoding.DecodeString(key)
			if err != nil {
				log.Fatalf("Error decoding base64 key: %v", err)
			}
		}
		if len(e.Key) != 32 {
			log.Fatalln("Key must be 32 bytes")
		}
		file, err := ioutil.ReadFile(input)
		if err != nil {
			log.Fatal(err)
		}

		e.PlainText = file

		if err := e.Encrypt(); err != nil {
			log.Fatalf("Error encrypting file: %v", err)
		}
		e.WrapCrypto()
		if deleteFile {
			os.Remove(input)
		}
		if output == "" {
			output = fmt.Sprintf("%s.enc", input)
		}
		if err := ioutil.WriteFile(output, []byte(e.WrappedData), 0644); err != nil {
			log.Fatalf("Error writing encrypted file to disk: %v", err)
		}
	},
}

func init() {
	RootCmd.AddCommand(encryptCmd)

	encryptCmd.Flags().StringVarP(&input, "input", "i", "", "Name of file to encrypt - required")
	encryptCmd.Flags().StringVarP(&output, "output", "o", "", "Name of encrypted file to output")
	encryptCmd.Flags().StringVarP(&key, "key", "k", "", "Key to use for encryption")
	encryptCmd.Flags().BoolVarP(&deleteFile, "delete", "d", false, "Delete original file after encryption, if successful")
}
