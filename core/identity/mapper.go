package identity

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// ReflectionMapper implements the Mapper interface using reflection.
type ReflectionMapper struct {
	factory  func() FlowIdentity
	mappings map[string]string // logical key -> struct field name
}

// NewReflectionMapper creates a new ReflectionMapper.
func NewReflectionMapper(factory func() FlowIdentity) *ReflectionMapper {
	return &ReflectionMapper{
		factory:  factory,
		mappings: make(map[string]string),
	}
}

// MapField registers a mapping between a logical key and a struct field.
func (m *ReflectionMapper) MapField(key, field string) {
	m.mappings[key] = field
}

// MapTraits extracts traits from the identity struct using the registered mappings.
func (m *ReflectionMapper) MapTraits(ident FlowIdentity) (JSON, error) {
	traits := make(map[string]any)
	v := reflect.ValueOf(ident)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	// 1. Map registered fields
	for key, field := range m.mappings {
		f := v.FieldByName(field)
		if f.IsValid() {
			traits[key] = f.Interface()
		}
	}

	// 2. Map dynamic traits if TraitSource is implemented
	if ts, ok := ident.(TraitSource); ok {
		tJSON := ts.GetTraits()
		if len(tJSON) > 0 {
			var secondary map[string]any
			if err := json.Unmarshal(tJSON, &secondary); err == nil {
				for k, val := range secondary {
					// Don't overwrite explicit field mappings
					if _, exists := traits[k]; !exists {
						traits[k] = val
					}
				}
			}
		}
	}

	return json.Marshal(traits)
}

// UnmapTraits populates the identity struct from the provided traits.
func (m *ReflectionMapper) UnmapTraits(ident FlowIdentity, traits JSON) error {
	var data map[string]any
	if err := json.Unmarshal(traits, &data); err != nil {
		return fmt.Errorf("identity: failed to unmarshal traits: %w", err)
	}

	v := reflect.ValueOf(ident)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	unmapped := make(map[string]any)

	for key, val := range data {
		field, mapped := m.mappings[key]
		if mapped {
			f := v.FieldByName(field)
			if f.IsValid() && f.CanSet() {
				valV := reflect.ValueOf(val)
				if valV.Type().AssignableTo(f.Type()) {
					f.Set(valV)
				} else {
					// Tentative conversion for common types (e.g. float64 from JSON to int)
					if f.Kind() == reflect.Int {
						if f64, ok := val.(float64); ok {
							f.SetInt(int64(f64))
						}
					} else {
						// Fallback to string representation if target is string
						if f.Kind() == reflect.String {
							f.SetString(fmt.Sprintf("%v", val))
						}
					}
				}
				continue
			}
		}
		unmapped[key] = val
	}

	// Save unmapped traits to TraitSource if supported
	if ts, ok := ident.(TraitSource); ok && len(unmapped) > 0 {
		b, _ := json.Marshal(unmapped)
		ts.SetTraits(JSON(b))
	}

	return nil
}

// Validate checks if all registered mappings point to valid fields in the model.
func (m *ReflectionMapper) Validate() error {
	ident := m.factory()
	v := reflect.ValueOf(ident)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	for key, field := range m.mappings {
		f := v.FieldByName(field)
		if !f.IsValid() {
			return fmt.Errorf("identity: field '%s' (mapped to '%s') not found in model %T", field, key, ident)
		}
	}
	return nil
}
