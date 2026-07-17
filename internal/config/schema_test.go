package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestSchemaCoversConfig guards api/hamnir.schema.json against drifting from
// the Go config structs: with additionalProperties:false in the schema, any
// yaml key parsed here but missing there makes editors flag valid configs.
func TestSchemaCoversConfig(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "hamnir.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	child := func(node map[string]any, key string) map[string]any {
		c, _ := node[key].(map[string]any)
		return c
	}
	props := func(node map[string]any) map[string]any {
		return child(node, "properties")
	}
	root := props(schema)
	defs := child(schema, "$defs")

	tests := []struct {
		name   string
		typ    reflect.Type
		schema map[string]any
	}{
		{"config", reflect.TypeFor[Config](), root},
		{"client", reflect.TypeFor[Client](), props(child(defs, "client"))},
		{"group", reflect.TypeFor[Group](), props(child(defs, "group"))},
		{"persona", reflect.TypeFor[Persona](), props(child(defs, "persona"))},
		{"static", reflect.TypeFor[Static](), props(child(root, "static"))},
		{"lifetimes", reflect.TypeFor[Lifetimes](), props(child(root, "lifetimes"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.schema) == 0 {
				t.Fatal("schema section missing or empty")
			}
			for field := range tt.typ.Fields() {
				tag, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
				if tag == "" || tag == "-" {
					continue
				}
				if _, ok := tt.schema[tag]; !ok {
					t.Errorf("schema is missing property %q (struct field %s)", tag, field.Name)
				}
			}
		})
	}
}
