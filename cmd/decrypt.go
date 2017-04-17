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

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypts the specified file",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(key) != 32 {
			log.Fatalln("Key must be 32 bytes")
		}
		file, err := ioutil.ReadFile(input)
		if err != nil {
			log.Fatal(err)
		}
		e := crypto.EncryptionObject{
			Key:         key,
			WrappedData: string(file),
		}
		if err := e.UnwrapCrypto(); err != nil {
			log.Fatalf("Error unwrapping encrypted file: %v", err)
		}
		if err := e.Decrypt(); err != nil {
			log.Fatalf("Error decrypting file: %v", err)
		}
		if err := ioutil.WriteFile(output, e.PlainText, 0644); err != nil {
			log.Fatalf("Error writing file to disk: %v", err)
		}
		if deleteFile {
			os.Remove(input)
		}
	},
}

func init() {
	RootCmd.AddCommand(decryptCmd)

	decryptCmd.Flags().StringVarP(&input, "input", "i", "config.hcl.enc", "Name of encrypted file to decrypt")
	decryptCmd.Flags().StringVarP(&output, "output", "o", "config.hcl", "Name of file to output")
	decryptCmd.Flags().StringVarP(&key, "key", "k", "", "Key to use for decryption")
	decryptCmd.Flags().BoolVarP(&deleteFile, "delete", "d", false, "Delete original file after decryption, if successful")
}
