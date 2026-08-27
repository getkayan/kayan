package scim

import (
	"encoding/json"
	"testing"
)

func TestServiceProviderConfigAdvertisesOnlyImplementedFeatures(t *testing.T) {
	config := ServiceProviderConfig(250)
	if !config.Patch.Supported || !config.Filter.Supported {
		t.Fatal("PATCH and filtering must be advertised")
	}
	if config.Bulk.Supported || config.Sort.Supported || config.ETag.Supported {
		t.Fatal("unsupported capabilities were advertised")
	}
	if config.Filter.MaxResults != 250 {
		t.Fatalf("maxResults = %d, want 250", config.Filter.MaxResults)
	}
	if _, err := json.Marshal(config); err != nil {
		t.Fatalf("marshal config: %v", err)
	}
}

func TestDiscoveryIncludesUserAndGroup(t *testing.T) {
	resources := ResourceTypes()
	if len(resources) != 2 || resources[0].Endpoint != "/Users" || resources[1].Endpoint != "/Groups" {
		t.Fatalf("resource types = %#v", resources)
	}
	for _, id := range []string{UserSchema, GroupSchema} {
		schema, err := Schema(id)
		if err != nil {
			t.Fatalf("Schema(%q): %v", id, err)
		}
		if len(schema.Attributes) == 0 {
			t.Fatalf("Schema(%q) has no attributes", id)
		}
	}
}

func TestSchemaRejectsUnknownURN(t *testing.T) {
	if _, err := Schema("urn:example:missing"); err == nil {
		t.Fatal("expected unknown schema error")
	}
}
