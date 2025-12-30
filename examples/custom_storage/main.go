package main

import (
	"context"
	"fmt"
	"log"

	"github.com/getkayan/kayan/internal/api"
	"github.com/getkayan/kayan/internal/domain"
	"github.com/getkayan/kayan/internal/flow"
	"github.com/getkayan/kayan/internal/identity"
	"github.com/getkayan/kayan/internal/persistence"
	"github.com/getkayan/kayan/internal/session"
	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoStorage is an implementation of domain.Storage using the official MongoDB driver.
type MongoStorage struct {
	client *mongo.Client
	db     *mongo.Database
}

func (s *MongoStorage) CreateIdentity(id *identity.Identity) error {
	ctx := context.Background()
	_, err := s.db.Collection("identities").InsertOne(ctx, id)
	return err
}

func (s *MongoStorage) GetIdentity(id string) (*identity.Identity, error) {
	ctx := context.Background()
	var ident identity.Identity
	err := s.db.Collection("identities").FindOne(ctx, bson.M{"id": id}).Decode(&ident)
	if err != nil {
		return nil, err
	}
	return &ident, nil
}

func (s *MongoStorage) GetCredentialByIdentifier(identifier, method string) (*identity.Credential, error) {
	ctx := context.Background()
	var cred identity.Credential
	// Search in credentials array within identities or a separate collection
	err := s.db.Collection("identities").FindOne(ctx, bson.M{"credentials.identifier": identifier, "credentials.type": method}).Decode(&cred)
	if err != nil {
		return nil, err
	}
	return &cred, nil
}

func (s *MongoStorage) CreateSession(sess *identity.Session) error {
	ctx := context.Background()
	_, err := s.db.Collection("sessions").InsertOne(ctx, sess)
	return err
}

func (s *MongoStorage) GetSession(id string) (*identity.Session, error) {
	ctx := context.Background()
	var sess identity.Session
	err := s.db.Collection("sessions").FindOne(ctx, bson.M{"id": id}).Decode(&sess)
	return &sess, err
}

func (s *MongoStorage) DeleteSession(id string) error {
	ctx := context.Background()
	_, err := s.db.Collection("sessions").DeleteOne(ctx, bson.M{"id": id})
	return err
}

func init() {
	persistence.Register("mongodb", func(dsn string, extra interface{}) (domain.Storage, error) {
		ctx := context.Background()
		client, err := mongo.Connect(ctx, options.Client().ApplyURI(dsn))
		if err != nil {
			return nil, err
		}
		return &MongoStorage{
			client: client,
			db:     client.Database("kayan"),
		}, nil
	})
}

func main() {
	// 2. Initialize storage using our custom "mongodb" registry entry.
	dbType := "mongodb"
	dsn := "mongodb://localhost:27017"

	storage, err := persistence.NewStorage(dbType, dsn, nil)
	if err != nil {
		log.Fatalf("failed to initialize storage: %v", err)
	}

	// 3. Wire the rest of Kayan
	regManager := flow.NewRegistrationManager(storage)
	logManager := flow.NewLoginManager(storage)
	sessionManager := session.NewManager(storage)

	// Register Password Strategy
	hasher := flow.NewBcryptHasher(14)
	pwStrategy := flow.NewPasswordStrategy(storage, hasher)
	regManager.RegisterStrategy(pwStrategy)
	logManager.RegisterStrategy(pwStrategy)

	// 4. Initialize API Handler with our "Mongo" Managers
	h := api.NewHandler(regManager, logManager, sessionManager, nil)

	// 5. Setup Echo and Routes
	e := echo.New()
	e.HideBanner = true
	g := e.Group("/api/v1")
	h.RegisterRoutes(g)

	fmt.Println("Kayan is now running with custom MongoDB storage!")
	fmt.Println("Try hitting: POST http://localhost:8080/api/v1/registration")

	if err := e.Start(":8080"); err != nil {
		log.Fatal(err)
	}
}
