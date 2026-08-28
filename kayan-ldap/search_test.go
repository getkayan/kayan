package ldapstore

import (
	"errors"
	"strings"
	"testing"

	"github.com/getkayan/kayan/core/flow"
	"github.com/go-ldap/ldap/v3"
)

// stubClient stands in for a directory. searchErr is returned alongside
// result, which is the combination a real size-limit refusal produces: the
// entries the server did send, plus the code saying it stopped early.
type stubClient struct {
	lastRequest *ldap.SearchRequest
	result      *ldap.SearchResult
	searchErr   error
}

func (c *stubClient) Bind(username, password string) error { return nil }
func (c *stubClient) Close() error                         { return nil }

func (c *stubClient) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	c.lastRequest = req
	return c.result, c.searchErr
}

func entriesResult(dns ...string) *ldap.SearchResult {
	result := &ldap.SearchResult{}
	for _, dn := range dns {
		result.Entries = append(result.Entries, &ldap.Entry{DN: dn})
	}
	return result
}

// TestTruncatedSearchIsReportedNotSwallowed is the property the size limit
// exists for.
//
// Active Directory applies MaxPageSize -- 1000 by default -- to any search
// without the paged-results control. It answers with that many entries and
// the sizeLimitExceeded code. Returning those entries as an ordinary result
// would tell a caller asking "is this username unique?" that it is, on the
// strength of a list the directory had stopped filling.
func TestTruncatedSearchIsReportedNotSwallowed(t *testing.T) {
	stub := &stubClient{
		result:    entriesResult("uid=alice,ou=a,dc=example,dc=com", "uid=alice,ou=b,dc=example,dc=com"),
		searchErr: ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("size limit exceeded")),
	}
	conn := &Conn{conn: stub}

	entries, err := conn.Search(flow.LDAPSearchRequest{
		BaseDN: "dc=example,dc=com", Filter: "(uid=alice)", SizeLimit: 2,
	})

	if err == nil {
		t.Fatal("a truncated result was returned as a complete one")
	}
	if !errors.Is(err, flow.ErrLDAPResultTruncated) {
		t.Errorf("error = %v, want flow.ErrLDAPResultTruncated", err)
	}
	// The entries must survive: the strategy decides ambiguity from the error,
	// but a caller that logs the result needs to see what arrived.
	if len(entries) != 2 {
		t.Errorf("got %d entries, want the 2 the directory did send", len(entries))
	}
}

// TestSizeLimitReachesTheDirectory proves the cap is sent rather than applied
// after the fact. A limit enforced only client-side still lets the server
// stream an entire subtree across the wire first.
func TestSizeLimitReachesTheDirectory(t *testing.T) {
	stub := &stubClient{result: entriesResult("uid=alice,ou=staff,dc=example,dc=com")}
	conn := &Conn{conn: stub}

	if _, err := conn.Search(flow.LDAPSearchRequest{
		BaseDN: "dc=example,dc=com", Filter: "(uid=alice)", SizeLimit: 2,
	}); err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	if stub.lastRequest.SizeLimit != 2 {
		t.Errorf("SizeLimit on the wire = %d, want 2", stub.lastRequest.SizeLimit)
	}
}

// TestSearchFailureDiscardsPartialResults keeps the truncation path narrow.
// Any error other than a size limit means the result is not a shortened
// answer but an unfinished one, and returning its entries would present
// fragments of a failed query as findings.
func TestSearchFailureDiscardsPartialResults(t *testing.T) {
	stub := &stubClient{
		result:    entriesResult("uid=alice,ou=a,dc=example,dc=com"),
		searchErr: ldap.NewError(ldap.LDAPResultBusy, errors.New("server busy")),
	}
	conn := &Conn{conn: stub}

	entries, err := conn.Search(flow.LDAPSearchRequest{BaseDN: "dc=example,dc=com", Filter: "(uid=alice)"})
	if err == nil {
		t.Fatal("a failed search returned no error")
	}
	if errors.Is(err, flow.ErrLDAPResultTruncated) {
		t.Error("an unrelated failure was reported as a truncation, which a caller " +
			"reads as a definite answer that was merely shortened")
	}
	if entries != nil {
		t.Errorf("got %d entries from a failed search, want none", len(entries))
	}
	if !strings.Contains(err.Error(), "server busy") {
		t.Errorf("error = %v, want it to carry the directory's cause", err)
	}
}

// TestUnlimitedSearchLeavesTheDirectorysOwnLimit covers the default. Zero must
// mean "no client limit", not "limit of zero", which some encodings would
// turn into an empty result.
func TestUnlimitedSearchLeavesTheDirectorysOwnLimit(t *testing.T) {
	stub := &stubClient{result: entriesResult("uid=alice,ou=staff,dc=example,dc=com")}
	conn := &Conn{conn: stub}

	entries, err := conn.Search(flow.LDAPSearchRequest{BaseDN: "dc=example,dc=com", Filter: "(uid=alice)"})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("got %d entries, want 1", len(entries))
	}
	if stub.lastRequest.SizeLimit != 0 {
		t.Errorf("SizeLimit = %d, want 0 so the directory's own limit applies", stub.lastRequest.SizeLimit)
	}
}
