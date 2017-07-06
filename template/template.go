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

const hclSecretTemplate = `secret "{{ .Name }}" {
	path = "{{ .Path }}"
	data {
		{{ range $k, $v := .Data -}}
		{{ $k }} = "{{ $v }}"
		{{ end -}}
	}
}
`

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
	if v, ok := os.LookupEnv(key); ok {
		return v, nil
	}

	if v, ok := g.vars[key]; ok {
		return v, nil
	}

	return nil, fmt.Errorf("Variable %v not found", key)
}

func (g *Generator) templateLookupSecret(path string, targetPath ...string) (interface{}, error) {
	s, err := g.client.Logical().Read(path)
	if err != nil || s == nil {
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

	var buf bytes.Buffer
	tmpl := template.Must(template.New("secret").Parse(hclSecretTemplate))
	if err := tmpl.Execute(&buf, tmplSecret); err != nil {
		panic(err)
	}

	return buf.String(), nil
}

func InitGenerator(varsFile string, config []byte) *Generator {
	var err error
	g := Generator{
		config: config,
	}
	g.client, err = vault.NewClient(nil)
	if err != nil {
		panic(err)
	}
	g.tmpl = template.New("").Funcs(template.FuncMap{
		"Lookup":       g.templateLookup,
		"LookupSecret": g.templateLookupSecret,
	})

	g.readVars(varsFile)

	return &g
}

func (g *Generator) GenerateConfig() []byte {
	var buf bytes.Buffer
	template.Must(g.tmpl.Parse(string(g.config)))
	if err := g.tmpl.Execute(&buf, g.vars); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return buf.Bytes()
}

func (g *Generator) readVars(filename string) {
	_, err := os.Stat(filename)
	if err != nil {
		return
	}
	vars, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	if err := hcl.Unmarshal(vars, &g.vars); err != nil {
		panic(err)
	}
}
