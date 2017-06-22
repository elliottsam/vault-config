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

	"strings"

	"fmt"

	"github.com/elliottsam/vault-config/crypto"
	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypts the specified file",
	Long: `Decrypts a file using the specified key, if the
delete flag is set to true, this will also delete
the original file

The key specified needs to be 32 bytes long and
base 64 encoded

If the key is not specified it will be requested
from the command line

i.e.
vault-config decrypt -i config.vc.enc -k mSskqBC85rA65lofPOaQcVtjjnHJ16rI+/rqZfkBwqs=

Will encrypt the file 'config.vc.enc' to 'config.vc'`,
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

		e.WrappedData = string(file)

		if err := e.UnwrapCrypto(); err != nil {
			log.Fatalf("Error unwrapping encrypted file: %v", err)
		}
		if err := e.Decrypt(); err != nil {
			log.Fatalf("Error decrypting file: %v", err)
		}

		if deleteFile {
			os.Remove(input)
		}
		if output == "" {
			if strings.HasSuffix(input, ".enc") {
				output = strings.TrimSuffix(input, ".enc")
			} else {
				output = fmt.Sprintf("%s.dec", input)
			}
		}
		if err := ioutil.WriteFile(output, e.PlainText, 0644); err != nil {
			log.Fatalf("Error writing file to disk: %v", err)
		}
	},
}

func init() {
	RootCmd.AddCommand(decryptCmd)

	decryptCmd.Flags().StringVarP(&input, "input", "i", "", "Name of encrypted file to decrypt")
	decryptCmd.Flags().StringVarP(&output, "output", "o", "", "Name of file to output")
	decryptCmd.Flags().StringVarP(&key, "key", "k", "", "Key to use for decryption")
	decryptCmd.Flags().BoolVarP(&deleteFile, "delete", "d", false, "Delete original file after decryption, if successful")
}
