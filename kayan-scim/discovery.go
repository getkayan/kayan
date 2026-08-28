package scim

import "fmt"

const (
	ServiceProviderConfigSchema = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	ResourceTypeSchema          = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaResourceSchema        = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

// SupportedFeature describes a SCIM service-provider capability.
type SupportedFeature struct {
	Supported bool `json:"supported"`
}

// FilterSupport describes filter support and the maximum returned resources.
type FilterSupport struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

// AuthenticationScheme describes one authentication mechanism selected by the host.
type AuthenticationScheme struct {
	Type             string `json:"type"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	SpecURI          string `json:"specUri,omitempty"`
	DocumentationURI string `json:"documentationUri,omitempty"`
	Primary          bool   `json:"primary"`
}

// ServiceProviderConfiguration is the RFC 7643 discovery resource.
type ServiceProviderConfiguration struct {
	Schemas               []string               `json:"schemas"`
	DocumentationURI      string                 `json:"documentationUri,omitempty"`
	Patch                 SupportedFeature       `json:"patch"`
	Bulk                  SupportedFeature       `json:"bulk"`
	Filter                FilterSupport          `json:"filter"`
	ChangePassword        SupportedFeature       `json:"changePassword"`
	Sort                  SupportedFeature       `json:"sort"`
	ETag                  SupportedFeature       `json:"etag"`
	AuthenticationSchemes []AuthenticationScheme `json:"authenticationSchemes"`
}

// ResourceType describes one provisionable SCIM resource.
type ResourceType struct {
	Schemas          []string          `json:"schemas"`
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	Endpoint         string            `json:"endpoint"`
	Schema           string            `json:"schema"`
	SchemaExtensions []SchemaExtension `json:"schemaExtensions"`
}

// SchemaExtension associates an extension schema with a resource type.
type SchemaExtension struct {
	Schema   string `json:"schema"`
	Required bool   `json:"required"`
}

// SchemaDefinition describes a SCIM resource schema.
type SchemaDefinition struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Attributes  []SchemaAttribute `json:"attributes"`
}

// SchemaAttribute describes an attribute exposed through schema discovery.
type SchemaAttribute struct {
	Name          string            `json:"name"`
	Type          string            `json:"type"`
	MultiValued   bool              `json:"multiValued"`
	Description   string            `json:"description,omitempty"`
	Required      bool              `json:"required"`
	CaseExact     bool              `json:"caseExact"`
	Mutability    string            `json:"mutability"`
	Returned      string            `json:"returned"`
	Uniqueness    string            `json:"uniqueness"`
	SubAttributes []SchemaAttribute `json:"subAttributes,omitempty"`
}

// ServiceProviderConfig returns Kayan's transport-neutral discovery resource.
// The host may append its authentication schemes and documentation URI.
//
// etag is reported as unsupported. Use [Manager.ServiceProviderConfig], which
// asks the configured storage: a client that reads etag: true starts sending
// If-Match and expects 412 on a conflict, and against storage that cannot
// compare and swap every one of those requests would be answered as though the
// precondition held.
func ServiceProviderConfig(maxResults int) ServiceProviderConfiguration {
	if maxResults <= 0 {
		maxResults = 100
	}
	return ServiceProviderConfiguration{
		Schemas:               []string{ServiceProviderConfigSchema},
		Patch:                 SupportedFeature{Supported: true},
		Bulk:                  SupportedFeature{Supported: false},
		Filter:                FilterSupport{Supported: true, MaxResults: maxResults},
		ChangePassword:        SupportedFeature{Supported: false},
		Sort:                  SupportedFeature{Supported: false},
		ETag:                  SupportedFeature{Supported: false},
		AuthenticationSchemes: []AuthenticationScheme{},
	}
}

// ResourceTypes returns the built-in User and Group discovery resources.
func ResourceTypes() []ResourceType {
	return []ResourceType{
		{Schemas: []string{ResourceTypeSchema}, ID: "User", Name: "User", Description: "User Account", Endpoint: "/Users", Schema: UserSchema, SchemaExtensions: []SchemaExtension{}},
		{Schemas: []string{ResourceTypeSchema}, ID: "Group", Name: "Group", Description: "Group", Endpoint: "/Groups", Schema: GroupSchema, SchemaExtensions: []SchemaExtension{}},
	}
}

// Schemas returns the built-in User and Group schema definitions.
func Schemas() []SchemaDefinition {
	return []SchemaDefinition{userSchemaDefinition(), groupSchemaDefinition()}
}

// Schema returns one built-in schema by URN.
func Schema(id string) (SchemaDefinition, error) {
	for _, schema := range Schemas() {
		if schema.ID == id {
			return schema, nil
		}
	}
	return SchemaDefinition{}, fmt.Errorf("scim: schema %q not found", id)
}

func userSchemaDefinition() SchemaDefinition {
	return SchemaDefinition{
		Schemas: []string{SchemaResourceSchema}, ID: UserSchema, Name: "User", Description: "User Account",
		Attributes: []SchemaAttribute{
			attribute("userName", "string", false, true, "readWrite", "default", "server"),
			attribute("displayName", "string", false, false, "readWrite", "default", "none"),
			attribute("active", "boolean", false, false, "readWrite", "default", "none"),
			{
				Name: "name", Type: "complex", MultiValued: false, Mutability: "readWrite", Returned: "default", Uniqueness: "none",
				SubAttributes: []SchemaAttribute{
					attribute("formatted", "string", false, false, "readWrite", "default", "none"),
					attribute("familyName", "string", false, false, "readWrite", "default", "none"),
					attribute("givenName", "string", false, false, "readWrite", "default", "none"),
				},
			},
			{
				Name: "emails", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default", Uniqueness: "none",
				SubAttributes: []SchemaAttribute{
					attribute("value", "string", false, false, "readWrite", "default", "none"),
					attribute("type", "string", false, false, "readWrite", "default", "none"),
					attribute("primary", "boolean", false, false, "readWrite", "default", "none"),
				},
			},
		},
	}
}

func groupSchemaDefinition() SchemaDefinition {
	return SchemaDefinition{
		Schemas: []string{SchemaResourceSchema}, ID: GroupSchema, Name: "Group", Description: "Group",
		Attributes: []SchemaAttribute{
			attribute("displayName", "string", false, true, "readWrite", "default", "none"),
			{
				Name: "members", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default", Uniqueness: "none",
				SubAttributes: []SchemaAttribute{
					attribute("value", "string", false, false, "immutable", "default", "none"),
					attribute("$ref", "reference", false, false, "immutable", "default", "none"),
					attribute("type", "string", false, false, "immutable", "default", "none"),
				},
			},
		},
	}
}

func attribute(name, valueType string, multiValued, required bool, mutability, returned, uniqueness string) SchemaAttribute {
	return SchemaAttribute{Name: name, Type: valueType, MultiValued: multiValued, Required: required, Mutability: mutability, Returned: returned, Uniqueness: uniqueness}
}

// ServiceProviderConfig returns the discovery resource for this deployment,
// with the features the configured storage can actually serve.
//
// Advertising a capability that is not implemented is an interoperability bug
// that surfaces inside the client, where it is hard to diagnose -- and for
// etag it is worse than that: the client sends If-Match believing its update
// is guarded, and the update it is guarding against still happens.
func (m *Manager) ServiceProviderConfig(maxResults int) ServiceProviderConfiguration {
	config := ServiceProviderConfig(maxResults)
	config.ETag = SupportedFeature{Supported: m.SupportsConditionalWrites()}
	return config
}
