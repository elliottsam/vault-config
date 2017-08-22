package crypto

import (
	"bytes"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
)

func (e *EncryptionObject) InlineEncryptMap(path string) error {
	astFile, err := hcl.ParseBytes(e.PlainText)
	if err != nil {
		return fmt.Errorf("Error parsing HCL into *ast.File: %v", err)
	}

	data := findKeyInObject(astFile.Node.(*ast.ObjectList).Items, path)
	for _, v := range data {
		if !wrappedCipherRegex.MatchString(v.Val.(*ast.LiteralType).Token.Text) {
			s, err := EncryptString(strings.Trim(v.Val.(*ast.LiteralType).Token.Text, "\""), e.Key)
			if err != nil {
				return fmt.Errorf("Error encrypting string: %v", err)
			}
			v.Val.(*ast.LiteralType).Token.Text = fmt.Sprintf("\"%s\"", s)
		} else {
			log.Printf("Key: %v appears to already be encrypted, skipping inline encryption", v.Keys[0].GoString())
		}
	}

	var buf bytes.Buffer
	if err := printer.Fprint(&buf, astFile); err != nil {
		return fmt.Errorf("Error writing to buffer: %v", err)
	}

	e.CipherText = buf.Bytes()

	return nil
}

func findKeyInObject(obj []*ast.ObjectItem, key string) []*ast.ObjectItem {
	ks := strings.Split(key, "/")
	for _, k := range ks {
		var loopObj []*ast.ObjectItem
		for _, v := range obj {
			if keysContain(v.Keys, k) {
				loopObj = append(loopObj, v.Val.(*ast.ObjectType).List.Items...)
			}
		}
		obj = loopObj
	}

	return obj
}

func keysContain(k []*ast.ObjectKey, value string) bool {
	for _, v := range k {
		if v.Token.Text == value {
			return true
		}
	}

	return false
}
