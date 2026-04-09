package scim

import (
	"encoding/json"
	"testing"

	"github.com/getkayan/kayan/core/identity"
)

type TestUser struct {
	ID    string
	Email string
	Name  string
	Traits identity.JSON
}

func (u *TestUser) GetID() any { return u.ID }
func (u *TestUser) SetID(id any) { u.ID = id.(string) }
func (u *TestUser) GetTraits() identity.JSON { return u.Traits }
func (u *TestUser) SetTraits(t identity.JSON) { u.Traits = t }

func TestMapper(t *testing.T) {
	factory := func() any { return &TestUser{} }
	config := MapperConfig{
		FieldMappings: map[string]string{
			"userName": "Email",
			"displayName": "Name",
		},
		TraitMappings: map[string]string{
			"name.givenName": "first_name",
			"name.familyName": "last_name",
		},
	}

	mapper := NewMapper(factory, config)

	// Test ToModel
	scimUser := NewUser()
	scimUser.ID = "user-123"
	scimUser.UserName = "jane@example.com"
	scimUser.DisplayName = "Jane Doe"
	scimUser.Name = &Name{
		GivenName:  "Jane",
		FamilyName: "Doe",
	}

	model, err := mapper.ToModel(scimUser)
	if err != nil {
		t.Fatalf("ToModel failed: %v", err)
	}

	tu := model.(*TestUser)
	if tu.ID != "user-123" {
		t.Errorf("Expected ID user-123, got %s", tu.ID)
	}
	if tu.Email != "jane@example.com" {
		t.Errorf("Expected Email jane@example.com, got %s", tu.Email)
	}
	if tu.Name != "Jane Doe" {
		t.Errorf("Expected Name Jane Doe, got %s", tu.Name)
	}

	var traits map[string]any
	json.Unmarshal(tu.Traits, &traits)
	if traits["first_name"] != "Jane" {
		t.Errorf("Expected trait first_name Jane, got %v", traits["first_name"])
	}
	if traits["last_name"] != "Doe" {
		t.Errorf("Expected trait last_name Doe, got %v", traits["last_name"])
	}

	// Test FromModel
	backToScim, err := mapper.FromModel(tu)
	if err != nil {
		t.Fatalf("FromModel failed: %v", err)
	}

	if backToScim.UserName != "jane@example.com" {
		t.Errorf("Expected SCIM userName jane@example.com, got %s", backToScim.UserName)
	}
	if backToScim.Name.GivenName != "Jane" {
		t.Errorf("Expected SCIM givenName Jane, got %s", backToScim.Name.GivenName)
	}
}
