package template

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"text/template"

	"github.com/elliottsam/vault-config/vault"
	"github.com/hashicorp/hcl"
)

type Generator struct {
	vars   map[string]interface{}
	config []byte
	client *vault.VCClient
	tmpl   *template.Template
}

type secret struct {
	Name string
	Path string
	Data map[string]interface{}
}

func (g *Generator) templateLookup(key string) (interface{}, error) {
	if g.vars[key] == nil {
		return nil, fmt.Errorf("Variable %v not found", key)
	}

	return g.vars[key], nil
}

func (g *Generator) templateLookupSecret(path string, targetPath ...string) (interface{}, error) {
	s, err := g.client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("reading from vault path: %s\nError: %v", path, err)
	}
	tmplSecret := secret{
		Path: path,
		Data: s.Data,
	}
	if len(targetPath) > 0 {
		tmplSecret.Path = targetPath[0]
	}
	sp := strings.Split(tmplSecret.Path, "/")
	tmplSecret.Name = sp[len(sp)-1]

	hclTemplate := `secret "{{ .Name }}" {
	path = "{{ .Path }}"
	data {
		{{ range $k, $v := .Data -}}
		{{ $k }} = "{{ $v }}"
		{{ end -}}
	}
}

`
	var buf bytes.Buffer
	tmpl := template.Must(template.New("secret").Parse(hclTemplate))
	if err := tmpl.Execute(&buf, tmplSecret); err != nil {
		panic(err)
	}

	return buf.String(), nil
}

func InitGenerator(varsFile string, config []byte) *Generator {
	g := Generator{
		config: config,
	}
	c, err := vault.NewClient(nil)
	if err != nil {
		panic(err)
	}
	g.client = c
	g.tmpl = template.New("").Funcs(template.FuncMap{
		"Lookup":       g.templateLookup,
		"LookupSecret": g.templateLookupSecret,
	})

	g.vars = readVars(varsFile)

	return &g
}

func (g *Generator) GenerateConfig() ([]byte, error) {
	var buf bytes.Buffer
	g.tmpl.Parse(string(g.config))
	if err := g.tmpl.Execute(&buf, g.vars); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return buf.Bytes(), nil
}

func readVars(filename string) (output map[string]interface{}) {
	_, err := os.Stat(filename)
	if err != nil {
		return
	}
	vars, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	if err := hcl.Unmarshal(vars, &output); err != nil {
		panic(err)
	}

	return
}
