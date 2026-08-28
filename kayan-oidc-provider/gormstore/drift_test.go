package gormstore

import (
	"context"
	"encoding/json"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/getkayan/kayan/kayan-oidc-provider/oauth2"
)

// This file guards one recurring failure: a field exists on the core type, the
// GORM model omits it, and the converters drop it silently.
//
// It has already happened twice. AuthCode.Nonce was dropped, which removed the
// ID-token nonce binding for every deployment on this adapter -- a replay
// defence that simply was not there, with nothing failing to say so. Then
// Client.PostLogoutRedirectURIs, which left RP-initiated logout refusing every
// redirect a deployment had registered.
//
// Neither was caught by the CRUD tests, because those set the fields they
// remember to set. These tests instead fill every exported field through
// reflection, so a field added tomorrow is covered without anyone adding a
// line here.

// fillStruct populates every exported field of the struct v points at with a
// non-zero value derived from seed, so a dropped field shows up as a zero.
func fillStruct(t *testing.T, v any, seed int64) {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	value := reflect.ValueOf(v).Elem()
	typ := value.Type()

	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		target := value.Field(i)
		switch {
		case field.Type == reflect.TypeOf(time.Time{}):
			// Whole seconds: some drivers do not keep sub-second precision,
			// and this test is about fields being carried, not about clocks.
			target.Set(reflect.ValueOf(time.Unix(1700000000+rng.Int63n(1000), 0).UTC()))
		case field.Type == reflect.TypeOf(json.RawMessage{}):
			target.Set(reflect.ValueOf(json.RawMessage(`{"keys":[]}`)))
		case field.Type.Kind() == reflect.String:
			target.SetString(field.Name + "-value")
		case field.Type.Kind() == reflect.Bool:
			target.SetBool(true)
		case field.Type.Kind() == reflect.Int || field.Type.Kind() == reflect.Int64:
			target.SetInt(int64(i) + 1)
		case field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.String:
			target.Set(reflect.ValueOf([]string{field.Name + "-a", field.Name + "-b"}))
		case field.Type.Kind() == reflect.Ptr && field.Type.Elem() == reflect.TypeOf(time.Time{}):
			when := time.Unix(1700000000+rng.Int63n(1000), 0).UTC()
			target.Set(reflect.ValueOf(&when))
		default:
			t.Fatalf("fillStruct does not know how to fill %s.%s (%s); "+
				"extend it rather than skipping the field, or the drift this "+
				"test exists to catch will pass through it",
				typ.Name(), field.Name, field.Type)
		}
	}
}

// diffFields reports the exported fields where want and got disagree.
func diffFields(t *testing.T, want, got any) []string {
	t.Helper()
	wantValue := reflect.ValueOf(want).Elem()
	gotValue := reflect.ValueOf(got).Elem()
	typ := wantValue.Type()

	var dropped []string
	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		if !reflect.DeepEqual(wantValue.Field(i).Interface(), gotValue.Field(i).Interface()) {
			dropped = append(dropped, field.Name)
		}
	}
	return dropped
}

// TestClientSurvivesAConverterRoundTrip.
//
// PostLogoutRedirectURIs was the field this found: registered, dropped on the
// way into the database, and gone on the way out, so RP-initiated logout
// refused every redirect target a deployment had configured and looked like a
// misconfiguration on their side.
func TestClientSurvivesAConverterRoundTrip(t *testing.T) {
	want := &oauth2.Client{}
	fillStruct(t, want, 1)

	got := toCoreClient(fromCoreClient(want))

	if dropped := diffFields(t, want, got); len(dropped) > 0 {
		t.Errorf("the GORM adapter drops %v from oauth2.Client; a deployment on this "+
			"store silently loses whatever those fields control", dropped)
	}
}

// TestAuthCodeSurvivesAConverterRoundTrip. Nonce was the field this found. Its
// absence removed the ID-token nonce binding, so a captured ID token replayed
// into a fresh login could not be detected.
func TestAuthCodeSurvivesAConverterRoundTrip(t *testing.T) {
	want := &oauth2.AuthCode{}
	fillStruct(t, want, 2)

	got := toCoreAuthCode(fromCoreAuthCode(want))

	if dropped := diffFields(t, want, got); len(dropped) > 0 {
		t.Errorf("the GORM adapter drops %v from oauth2.AuthCode", dropped)
	}
}

func TestRefreshTokenSurvivesAConverterRoundTrip(t *testing.T) {
	want := &oauth2.RefreshToken{}
	fillStruct(t, want, 3)

	got := toCoreRefreshToken(fromCoreRefreshToken(want))

	if dropped := diffFields(t, want, got); len(dropped) > 0 {
		t.Errorf("the GORM adapter drops %v from oauth2.RefreshToken", dropped)
	}
}

// TestClientSurvivesTheDatabase covers the half a converter round trip cannot:
// a field the converters carry but the schema has no column for is lost on the
// way through storage, and only a real write and read back shows it.
func TestClientSurvivesTheDatabase(t *testing.T) {
	repo := setupRepo(t)
	ctx := context.Background()

	want := &oauth2.Client{}
	fillStruct(t, want, 4)

	if err := repo.CreateClient(ctx, want); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	got, err := repo.GetClient(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}

	if dropped := diffFields(t, want, got); len(dropped) > 0 {
		t.Errorf("%v did not survive a write and read back; the schema has no column "+
			"for them", dropped)
	}
}
