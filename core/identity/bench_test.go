package identity

import "testing"

type benchUser struct {
	ID    string
	Email string
	Name  string
	Age   int
}

func (u *benchUser) GetID() any   { return u.ID }
func (u *benchUser) SetID(id any) { u.ID = id.(string) }

func BenchmarkMapFields(b *testing.B) {
	mapper := NewReflectionMapper(func() FlowIdentity {
		return &benchUser{}
	})
	mapper.MapField("email", "Email")
	mapper.MapField("name", "Name")

	user := &benchUser{ID: "1", Email: "bench@example.com", Name: "Bench User", Age: 30}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mapper.MapTraits(user)
	}
}

func BenchmarkUnmapFields(b *testing.B) {
	mapper := NewReflectionMapper(func() FlowIdentity {
		return &benchUser{}
	})
	mapper.MapField("email", "Email")
	mapper.MapField("name", "Name")

	traits := JSON(`{"email":"bench@example.com","name":"Bench User"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		user := &benchUser{}
		mapper.UnmapTraits(user, traits)
	}
}
