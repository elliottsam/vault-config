package vault

import "github.com/fatih/structs"

func ConvertMapStringInterface(data interface{}) map[string]interface{} {
	f := structs.Fields(data)
	datamap := make(map[string]interface{})
	for _, v := range f {
		if v.Tag("mapstructure") != "" {
			if !v.IsZero() {
				datamap[v.Tag("mapstructure")] = v.Value()
			}
		}
	}

	return datamap
}
