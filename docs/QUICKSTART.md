# Quick Start

A working authentication service in about five minutes. For the reasoning
behind each step — and the choices you will eventually want to change — read
[Getting Started](./getting-started.md) afterwards.

Every sample here is typechecked against the real modules.

---

## Install

```bash
go get github.com/getkayan/kayan/core
go get github.com/getkayan/kayan/kayan-gorm
```

## The whole thing

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/session"
	gormstore "github.com/getkayan/kayan/kayan-gorm"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Your model. Kayan stores it as-is.
type User struct {
	ID    string `gorm:"primaryKey"`
	Email string `gorm:"uniqueIndex"`
}

func (u *User) GetID() any   { return u.ID }
func (u *User) SetID(id any) { u.ID = id.(string) }

type server struct {
	reg      *flow.RegistrationManager
	login    *flow.LoginManager
	sessions *session.Manager
}

func main() {
	db, err := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	repo := gormstore.NewRepository(db)
	if err := repo.AutoMigrateDev(&User{}); err != nil { // development only
		log.Fatal(err)
	}

	factory := func() any { return &User{} }

	reg, login := flow.PasswordAuth(repo, factory, "email",
		flow.WithPasswordPolicy(&flow.PasswordPolicy{
			MinLength:        12,
			RequireUppercase: true,
			RequireDigit:     true,
		}),
	)

	s := &server{
		reg:   reg,
		login: login,
		sessions: session.NewManager(
			session.NewHS256Strategy(sessionSecret(), 15*time.Minute),
		),
	}

	http.HandleFunc("/register", s.handleRegister)
	http.HandleFunc("/login", s.handleLogin)
	http.HandleFunc("/me", s.handleMe)

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	traits := identity.JSON(`{"email":"` + body.Email + `"}`)

	user, err := s.reg.Submit(r.Context(), "password", traits, body.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{"id": user.(*User).ID})
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	user, err := s.login.Authenticate(ctx, "password", body.Email, body.Password)
	if err != nil {
		// Deliberately the same response for "no such user" and "wrong
		// password". Distinguishing them lets an attacker enumerate accounts.
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	sess, err := s.sessions.Create(ctx, uuid.NewString(), user.(*User).ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]string{"token": sess.ID})
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")

	sess, err := s.sessions.Validate(r.Context(), token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]string{"user_id": sess.IdentityID})
}

// sessionSecret reads the signing secret from the environment.
//
// Never hardcode one. A secret committed in a sample is the one that ends up
// signing production sessions.
func sessionSecret() string {
	secret := os.Getenv("SESSION_SECRET")
	if secret == "" {
		log.Fatal("SESSION_SECRET is not set. Generate one with: openssl rand -base64 32")
	}
	return secret
}
```

## Run it

```bash
export SESSION_SECRET=$(openssl rand -base64 32)
go run .
```

```bash
curl -X POST localhost:8080/register \
  -d '{"email":"ada@example.com","password":"correct horse battery"}'

curl -X POST localhost:8080/login \
  -d '{"email":"ada@example.com","password":"correct horse battery"}'
# {"token":"eyJhbGci..."}

curl localhost:8080/me -H "Authorization: Bearer eyJhbGci..."
# {"user_id":"..."}
```

---

## What you just did

**Your struct is the user model.** No base type, no reserved columns. Kayan
addressed it through `GetID`/`SetID` and the factory. See
[BYOS](./concepts/byos.md).

**`PasswordAuth` wired registration and login together** with bcrypt at cost
12 and the password policy you specified. Every part of that is replaceable —
see [Strategies](./concepts/strategies.md).

**Sessions are stateless.** Validation is a signature check with no database
round trip, and the 15-minute expiry is doing real work, because a stateless
token cannot be revoked before it expires. When you need logout to mean
something, attach a revocation store or use the database strategy. See
[Sessions](./concepts/sessions.md).

**Kayan wrote no HTTP.** It parsed and validated; the handlers are yours. That
is what headless means here, and it is why this works identically behind chi,
gin, echo, or fiber.

---

## Before this is production

`AutoMigrateDev` is named for its environment. It cannot drop a column,
transform existing rows, or roll back — on a table holding accounts, a wrong
schema change is not recoverable. Use the versioned SQL instead:

```go notest
files, err := gormstore.Migrations(gormstore.DialectPostgres)
// Apply with golang-migrate, Atlas, goose, or your own runner.
```

The [production checklist](./getting-started.md#before-production) covers the
rest.

---

## Next

- [Getting Started](./getting-started.md) — the same ground with the reasoning
- [Authorization](./concepts/authorization.md) — deciding who may do what
- [Multi-Tenancy](./concepts/multi-tenancy.md) — serving several customers
- [examples/](../examples/README.md) — a runnable backend per strategy
- [core reference](./reference/core.md) — the whole API
