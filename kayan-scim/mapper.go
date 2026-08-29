package scim

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/getkayan/kayan/core/identity"
)

// Mapper handles conversion between SCIM resources and user models.
type Mapper struct {
	factory func() any
	config  MapperConfig
}

type MapperConfig struct {
	// FieldMappings maps SCIM field paths to struct field names.
	// Example: "userName" -> "Email"
	FieldMappings map[string]string
	// TraitMappings maps SCIM field paths to keys in the Traits JSON.
	// Example: "name.givenName" -> "first_name"
	TraitMappings map[string]string

	// MetaMappings maps SCIM meta members to struct field names on the
	// caller's model: [MetaCreated], [MetaLastModified], and [MetaVersion].
	//
	//	MetaMappings: map[string]string{
	//	    scim.MetaCreated:      "CreatedAt",
	//	    scim.MetaLastModified: "UpdatedAt",
	//	}
	//
	// They are mappings rather than library-owned columns because BYOS means
	// this package does not own the identity struct and cannot add fields to
	// it. An unmapped member is omitted from the response rather than
	// invented: a lastModified filled with the current time would tell a
	// provisioning connector that every resource changed on every sync.
	MetaMappings map[string]string

	// ResourceBaseURL is the SCIM service root, used to build meta.location.
	// For example "https://api.example.com/scim/v2".
	//
	// Kayan has no router and cannot discover the URL it is served under, so
	// without this the member is omitted. Guessing would put an address in the
	// response that resolves nowhere.
	ResourceBaseURL string
}

func NewMapper(factory func() any, config MapperConfig) *Mapper {
	if config.FieldMappings == nil {
		config.FieldMappings = make(map[string]string)
	}
	if config.TraitMappings == nil {
		config.TraitMappings = make(map[string]string)
	}
	if config.MetaMappings == nil {
		config.MetaMappings = make(map[string]string)
	}
	return &Mapper{
		factory: factory,
		config:  config,
	}
}

func (m *Mapper) Config() MapperConfig {
	return m.config
}

// ToModel converts a SCIM User to the target model.
func (m *Mapper) ToModel(user *User) (any, error) {
	model := m.factory()

	// Set standard ID if it exists and model implements FlowIdentity
	if fi, ok := model.(interface{ SetID(any) }); ok && user.ID != "" {
		fi.SetID(user.ID)
	}

	traits := make(map[string]any)

	// Strategy:
	// 1. Check FieldMappings (Direct struct field)
	// 2. Check TraitMappings (Traits JSON)

	// Helper to extract value from SCIM User using path
	extractValue := func(path string) any {
		return m.getScimValue(user, path)
	}

	for scimPath, structField := range m.config.FieldMappings {
		val := extractValue(scimPath)
		if val != nil {
			if err := m.setField(model, structField, val); err != nil {
				return nil, fmt.Errorf("failed to set field %s: %w", structField, err)
			}
		}
	}

	for scimPath, traitKey := range m.config.TraitMappings {
		val := extractValue(scimPath)
		if val != nil {
			traits[traitKey] = val
		}
	}

	// Update traits on model if it supports it
	if ts, ok := model.(interface{ SetTraits(identity.JSON) }); ok && len(traits) > 0 {
		b, _ := json.Marshal(traits)
		ts.SetTraits(identity.JSON(b))
	}

	return model, nil
}

// FromModel converts the target model to a SCIM User.
func (m *Mapper) FromModel(model any) (*User, error) {
	user := NewUser()

	// Set ID
	if fi, ok := model.(interface{ GetID() any }); ok {
		user.ID = fmt.Sprintf("%v", fi.GetID())
	}

	var traits map[string]any
	if ts, ok := model.(interface{ GetTraits() identity.JSON }); ok {
		if err := json.Unmarshal(ts.GetTraits(), &traits); err != nil {
			return nil, fmt.Errorf("scim: decode model traits: %w", err)
		}
	}

	// 1. Map from struct fields
	for scimPath, structField := range m.config.FieldMappings {
		val := m.getField(model, structField)
		if val != nil {
			m.setScimValue(user, scimPath, val)
		}
	}

	// 2. Map from traits
	for scimPath, traitKey := range m.config.TraitMappings {
		if val, ok := traits[traitKey]; ok {
			m.setScimValue(user, scimPath, val)
		}
	}

	// 3. Fill in meta. It is derived last so the version, when no version
	// field is mapped, hashes the fully populated resource.
	m.applyUserMeta(user, model)

	return user, nil
}

// applyUserMeta fills in user.Meta from the model and the mapper config.
func (m *Mapper) applyUserMeta(user *User, model any) {
	var created, lastModified time.Time
	if field, ok := m.config.MetaMappings[MetaCreated]; ok {
		if when, present := asTime(m.getField(model, field)); present {
			created = when
		}
	}
	if field, ok := m.config.MetaMappings[MetaLastModified]; ok {
		if when, present := asTime(m.getField(model, field)); present {
			lastModified = when
		}
	}

	version := ""
	if field, ok := m.config.MetaMappings[MetaVersion]; ok {
		version = asVersion(m.getField(model, field))
	}
	if version == "" {
		// No mapped version: hash the resource. Good enough to answer "has
		// this changed?", and deliberately not used for compare-and-swap --
		// see deriveVersion.
		version = deriveVersion(user)
	}

	applyMeta(&user.Meta, ResourceTypeUser, user.ID, m.config.ResourceBaseURL,
		created, lastModified, version)
}

// getScimValue extracts a value from SCIM struct using basic path (e.g. "name.givenName")
func (m *Mapper) getScimValue(user *User, path string) any {
	parts := strings.Split(path, ".")
	v := reflect.ValueOf(user).Elem()

	for _, part := range parts {
		// Handle simple fields
		f := v.FieldByName(exportedFieldName(part))
		if !f.IsValid() {
			return nil
		}
		if f.Kind() == reflect.Ptr {
			if f.IsNil() {
				return nil
			}
			v = f.Elem()
		} else {
			v = f
		}
	}

	if v.IsValid() {
		return v.Interface()
	}
	return nil
}

func (m *Mapper) setScimValue(user *User, path string, value any) {
	parts := strings.Split(path, ".")
	v := reflect.ValueOf(user).Elem()

	for i, part := range parts {
		name := exportedFieldName(part)
		f := v.FieldByName(name)
		if !f.IsValid() {
			return
		}

		if i == len(parts)-1 {
			// Final leaf
			if f.CanSet() {
				f.Set(reflect.ValueOf(value))
			}
			return
		}

		// Intermediate nested structs
		if f.Kind() == reflect.Ptr {
			if f.IsNil() {
				f.Set(reflect.New(f.Type().Elem()))
			}
			v = f.Elem()
		} else {
			v = f
		}
	}
}

func (m *Mapper) setField(obj any, field string, value any) error {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	f := v.FieldByName(field)
	if !f.IsValid() || !f.CanSet() {
		return fmt.Errorf("field %s not found or cannot be set", field)
	}

	val := reflect.ValueOf(value)
	if val.Type().AssignableTo(f.Type()) {
		f.Set(val)
	} else {
		// Basic attempt at conversion if needed (e.g. string to string)
		// but usually types should match
		f.Set(reflect.ValueOf(fmt.Sprintf("%v", value)))
	}
	return nil
}

func (m *Mapper) getField(obj any, field string) any {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	f := v.FieldByName(field)
	if !f.IsValid() {
		return nil
	}
	return f.Interface()
}

func (m *Mapper) ToModelPlaceholder() any {
	return m.factory()
}

// exportedFieldName converts a SCIM attribute name into the Go field name it
// maps to, by upper-casing the first rune: "givenName" becomes "GivenName".
//
// It replaces strings.Title, which is deprecated. The documented replacement,
// golang.org/x/text/cases, title-cases every word and would turn "givenName"
// into "Givenname" -- breaking every reflection lookup in this file. Only the
// first rune was ever significant here.
func exportedFieldName(attribute string) string {
	if attribute == "" {
		return ""
	}
	runes := []rune(attribute)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}
