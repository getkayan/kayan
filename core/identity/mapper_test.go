package identity

import (
	"encoding/json"
	"testing"
)

type MyUser struct {
	ID    string
	Email string
	Name  string
	Traits JSON
}

func (u *MyUser) GetID() any { return u.ID }
func (u *MyUser) SetID(id any) { u.ID = id.(string) }
func (u *MyUser) GetTraits() JSON { return u.Traits }
func (u *MyUser) SetTraits(t JSON) { u.Traits = t }

func TestReflectionMapper(t *testing.T) {
	mapper := NewReflectionMapper(func() FlowIdentity { return &MyUser{} })
	mapper.MapField("email", "Email")
	mapper.MapField("name", "Name")

	if err := mapper.Validate(); err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	user := &MyUser{
		ID:    "123",
		Email: "test@example.com",
		Name:  "Test User",
		Traits: JSON(`{"age": 30}`),
	}

	// Test Mapping (Struct -> JSON)
	traits, err := mapper.MapTraits(user)
	if err != nil {
		t.Fatalf("MapTraits failed: %v", err)
	}

	var m map[string]any
	json.Unmarshal(traits, &m)

	if m["email"] != "test@example.com" {
		t.Errorf("Expected email test@example.com, got %v", m["email"])
	}
	if m["name"] != "Test User" {
		t.Errorf("Expected name Test User, got %v", m["name"])
	}
	if int(m["age"].(float64)) != 30 {
		t.Errorf("Expected age 30, got %v", m["age"])
	}

	// Test Unmapping (JSON -> Struct)
	newUser := &MyUser{}
	input := JSON(`{"email": "new@example.com", "name": "New Name", "country": "US"}`)
	err = mapper.UnmapTraits(newUser, input)
	if err != nil {
		t.Fatalf("UnmapTraits failed: %v", err)
	}

	if newUser.Email != "new@example.com" {
		t.Errorf("Expected email new@example.com, got %s", newUser.Email)
	}
	if newUser.Name != "New Name" {
		t.Errorf("Expected name New Name, got %s", newUser.Name)
	}
	
	var traitsMap map[string]any
	json.Unmarshal(newUser.Traits, &traitsMap)
	if traitsMap["country"] != "US" {
		t.Errorf("Expected country US in dynamic traits, got %v", traitsMap["country"])
	}
}
