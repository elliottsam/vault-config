package vault

import "github.com/fatih/structs"

func ConvertMapStringString(data interface{}) map[string]string {
	f := structs.Fields(data)
	datamap := make(map[string]string)
	for _, v := range f {
		if v.Tag("mapstructure") != "" {
			datamap[v.Tag("mapstructure")] = v.Value().(string)
		}
	}

	return datamap
}

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
