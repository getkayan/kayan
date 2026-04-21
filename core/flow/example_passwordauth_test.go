package flow

import (
	"context"
	"fmt"

	"github.com/getkayan/kayan/core/identity"
)

func ExamplePasswordAuth() {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }

	reg, login := PasswordAuth(
		repo,
		factory,
		"email",
		WithHasherCost(4),
		WithIDGenerator(func() any { return "user-1" }),
	)

	traits := identity.JSON(`{"email":"dev@example.com"}`)
	registered, err := reg.Submit(context.Background(), "password", traits, "StrongPass123")
	if err != nil {
		fmt.Println("register error:", err)
		return
	}

	authenticated, err := login.Authenticate(context.Background(), "password", "dev@example.com", "StrongPass123")
	if err != nil {
		fmt.Println("login error:", err)
		return
	}

	fmt.Println("registered", registered.(*identity.Identity).ID)
	fmt.Println("authenticated", authenticated.(*identity.Identity).ID)
	// Output:
	// registered user-1
	// authenticated user-1
}
