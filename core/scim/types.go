package scim

import "time"

const (
	UserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	GroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
)

type Resource struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id,omitempty"`
	ExternalID string   `json:"externalId,omitempty"`
	Meta       Meta     `json:"meta,omitempty"`
}

type Meta struct {
	ResourceType string    `json:"resourceType,omitempty"`
	Created      time.Time `json:"created,omitempty"`
	LastModified time.Time `json:"lastModified,omitempty"`
	Location     string    `json:"location,omitempty"`
	Version      string    `json:"version,omitempty"`
}

type User struct {
	Resource
	UserName          string          `json:"userName"`
	Name              *Name           `json:"name,omitempty"`
	DisplayName       string          `json:"displayName,omitempty"`
	NickName          string          `json:"nickName,omitempty"`
	ProfileURL        string          `json:"profileUrl,omitempty"`
	Title             string          `json:"title,omitempty"`
	UserType          string          `json:"userType,omitempty"`
	PreferredLanguage string          `json:"preferredLanguage,omitempty"`
	Locale            string          `json:"locale,omitempty"`
	Timezone          string          `json:"timezone,omitempty"`
	Active            bool            `json:"active"`
	Password          string          `json:"password,omitempty"`
	Emails            []MultiValued   `json:"emails,omitempty"`
	PhoneNumbers      []MultiValued   `json:"phoneNumbers,omitempty"`
	Ims               []MultiValued   `json:"ims,omitempty"`
	Photos            []MultiValued   `json:"photos,omitempty"`
	Addresses         []Address       `json:"addresses,omitempty"`
	Groups            []MemberRef     `json:"groups,omitempty" scim:"readonly"`
	Entitlements      []MultiValued   `json:"entitlements,omitempty"`
	Roles             []MultiValued   `json:"roles,omitempty"`
	Certificates      []MultiValued   `json:"x509Certificates,omitempty"`
	ExtensionSchema   map[string]any `json:"-"`
}

type Name struct {
	Formatted       string `json:"formatted,omitempty"`
	FamilyName      string `json:"familyName,omitempty"`
	GivenName       string `json:"givenName,omitempty"`
	MiddleName      string `json:"middleName,omitempty"`
	HonorificPrefix string `json:"honorificPrefix,omitempty"`
	HonorificSuffix string `json:"honorificSuffix,omitempty"`
}

type MultiValued struct {
	Value   string `json:"value,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

type Address struct {
	Type          string `json:"type,omitempty"`
	StreetAddress string `json:"streetAddress,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postalCode,omitempty"`
	Country       string `json:"country,omitempty"`
	Formatted     string `json:"formatted,omitempty"`
	Primary       bool   `json:"primary,omitempty"`
}

type Group struct {
	Resource
	DisplayName string      `json:"displayName"`
	Members     []MemberRef `json:"members,omitempty"`
}

type MemberRef struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Type    string `json:"type,omitempty"` // User, Group
	Display string `json:"display,omitempty"`
}

type ListResponse struct {
	Schemas      []string   `json:"schemas"`
	TotalResults int        `json:"totalResults"`
	ItemsPerPage int        `json:"itemsPerPage"`
	StartIndex   int        `json:"startIndex"`
	Resources    []any      `json:"Resources"`
}

func NewUser() *User {
	return &User{
		Resource: Resource{
			Schemas: []string{UserSchema},
		},
	}
}

func NewGroup() *Group {
	return &Group{
		Resource: Resource{
			Schemas: []string{GroupSchema},
		},
	}
}
