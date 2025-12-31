package main

import (
	"context"
	"fmt"
	"log"

	"github.com/getkayan/kayan/api"
	"github.com/getkayan/kayan/flow"
	"github.com/getkayan/kayan/identity"
	"github.com/getkayan/kayan/session"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoStorage is an implementation of domain.Storage[T] using the official MongoDB driver.
type MongoStorage[T any] struct {
	client *mongo.Client
	db     *mongo.Database
}

func (s *MongoStorage[T]) CreateIdentity(id *identity.Identity[T]) error {
	ctx := context.Background()
	_, err := s.db.Collection("identities").InsertOne(ctx, id)
	return err
}

func (s *MongoStorage[T]) GetIdentity(id string) (*identity.Identity[T], error) {
	ctx := context.Background()
	var ident identity.Identity[T]
	err := s.db.Collection("identities").FindOne(ctx, bson.M{"id": id}).Decode(&ident)
	if err != nil {
		return nil, err
	}
	return &ident, nil
}

func (s *MongoStorage[T]) GetCredentialByIdentifier(identifier, method string) (*identity.Credential[T], error) {
	ctx := context.Background()
	var ident identity.Identity[T]
	// Find the identity that has the matching credential
	err := s.db.Collection("identities").FindOne(ctx, bson.M{
		"credentials.identifier": identifier,
		"credentials.type":       method,
	}).Decode(&ident)
	if err != nil {
		return nil, err
	}

	// Extract the specific credential from the list
	for _, cred := range ident.Credentials {
		if cred.Identifier == identifier && cred.Type == method {
			return &cred, nil
		}
	}

	return nil, fmt.Errorf("credential not found in identity")
}

func (s *MongoStorage[T]) CreateSession(sess *identity.Session[T]) error {
	ctx := context.Background()
	_, err := s.db.Collection("sessions").InsertOne(ctx, sess)
	return err
}

func (s *MongoStorage[T]) GetSession(id string) (*identity.Session[T], error) {
	ctx := context.Background()
	var sess identity.Session[T]
	err := s.db.Collection("sessions").FindOne(ctx, bson.M{"id": id}).Decode(&sess)
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *MongoStorage[T]) DeleteSession(id string) error {
	ctx := context.Background()
	_, err := s.db.Collection("sessions").DeleteOne(ctx, bson.M{"id": id})
	return err
}

func main() {
	// 1. Setup MongoDB
	ctx := context.Background()
	dsn := "mongodb+srv://admin:admin@testlab.fnrrluv.mongodb.net/?appName=testlab"
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(dsn))
	if err != nil {
		log.Fatalf("failed to connect to mongodb: %v", err)
	}

	// We'll use uuid.UUID as our ID type for this example
	storage := &MongoStorage[uuid.UUID]{
		client: client,
		db:     client.Database("kayan_mongodb"),
	}

	// 2. Wire the rest of Kayan
	regManager := flow.NewRegistrationManager[uuid.UUID](storage)
	logManager := flow.NewLoginManager[uuid.UUID](storage)
	sessionManager := session.NewManager[uuid.UUID](storage)

	// Register Password Strategy
	hasher := flow.NewBcryptHasher(14)
	pwStrategy := flow.NewPasswordStrategy[uuid.UUID](storage, hasher, "email")

	// Configure ID generation for UUIDs
	pwStrategy.SetIDGenerator(uuid.New)

	regManager.RegisterStrategy(pwStrategy)
	logManager.RegisterStrategy(pwStrategy)

	// 3. Initialize API Handler
	h := api.NewHandler[uuid.UUID](regManager, logManager, sessionManager, nil)

	// 4. Setup Echo and Routes
	e := echo.New()
	e.HideBanner = true
	g := e.Group("/api/v1")
	h.RegisterRoutes(g)

	fmt.Println("Kayan is now running with custom MongoDB storage (Generic ID: UUID)!")
	fmt.Println("Try hitting: POST http://localhost:8080/api/v1/registration")

	// Note: You would normally start the server here
	// if err := e.Start(":8080"); err != nil {
	// 	log.Fatal(err)
	// }
}
