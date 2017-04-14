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
	"os"

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

i.e.
vault-config encrypt -k n4y9jxgGkYbvkhQmWVYOkjx42nFPvcwx

Will encrypt the file 'config.hcl' to 'config.hcl.enc'`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(key) != 32 {
			log.Fatalln("Key must be 32 bytes")
		}
		file, err := ioutil.ReadFile(input)
		if err != nil {
			log.Fatal(err)
		}
		e := crypto.EncryptionObject{
			Key:       key,
			PlainText: file,
		}
		if err := e.Encrypt(); err != nil {
			log.Fatalf("Error encrypting file: %v", err)
		}
		e.WrapCrypto()
		if err := ioutil.WriteFile(output, []byte(e.WrappedData), 0644); err != nil {
			log.Fatalf("Error writing encrypted file to disk: %v", err)
		}
		if deleteFile {
			os.Remove(input)
		}
	},
}

func init() {
	RootCmd.AddCommand(encryptCmd)

	encryptCmd.Flags().StringVarP(&input, "input", "i", "config.hcl", "Name of file to encrypt")
	encryptCmd.Flags().StringVarP(&output, "output", "o", "config.hcl.enc", "Name of encrypted file to output")
	encryptCmd.Flags().StringVarP(&key, "key", "k", "", "Key to use for encryption")
	encryptCmd.Flags().BoolVarP(&deleteFile, "delete", "d", false, "Delete original file after encryption, if successful")
}
