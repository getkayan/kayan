package flow

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/getkayan/kayan/core/identity"
)

// TestLDAPFailsOverToTheNextReplica.
//
// A directory estate runs several servers. A strategy that knows one address
// makes any single host's maintenance window an authentication outage for the
// whole deployment.
func TestLDAPFailsOverToTheNextReplica(t *testing.T) {
	serving := &mockLDAPConn{entries: []LDAPEntry{
		{DN: "uid=alice,ou=staff,dc=example,dc=com",
			Attributes: map[string][]string{"mail": {"alice@example.com"}}},
	}}
	// The primary is absent from perAddr, so dialling it is refused.
	dialer := &mockLDAPDialer{perAddr: map[string]*mockLDAPConn{
		"replica-b:636": serving,
	}}

	config := defaultLDAPConfig()
	config.Addr = "replica-a:636"
	config.FailoverAddrs = []string{"replica-b:636"}
	strategy := NewLDAPStrategy(dialer, config, func() any { return &identity.Identity{} })

	ident, err := strategy.Authenticate(context.Background(), "alice", "password")
	if err != nil {
		t.Fatalf("Authenticate() error = %v, want the second replica to serve it", err)
	}
	if ident == nil {
		t.Fatal("no identity was returned")
	}
	if len(dialer.dialed) != 2 || dialer.dialed[0] != "replica-a:636" || dialer.dialed[1] != "replica-b:636" {
		t.Errorf("dialled %v, want the primary first then the failover", dialer.dialed)
	}
}

// TestLDAPDoesNotRetryARejectedPassword is the central test.
//
// A rejected bind is an answer, not an outage. Retrying it across the estate
// spends one failed-login count per replica, so a user who mistypes twice is
// locked out of a directory configured for three attempts -- and nothing in
// the logs explains the arithmetic, because each host only ever saw one
// attempt per try.
func TestLDAPDoesNotRetryARejectedPassword(t *testing.T) {
	rejected := errors.New("invalid credentials")
	userDN := "uid=alice,ou=staff,dc=example,dc=com"
	entries := []LDAPEntry{{DN: userDN}}
	primary := &mockLDAPConn{entries: entries, bindErr: map[string]error{userDN: rejected}}
	secondary := &mockLDAPConn{entries: entries, bindErr: map[string]error{userDN: rejected}}

	dialer := &mockLDAPDialer{perAddr: map[string]*mockLDAPConn{
		"replica-a:636": primary,
		"replica-b:636": secondary,
	}}

	config := defaultLDAPConfig()
	config.Addr = "replica-a:636"
	config.FailoverAddrs = []string{"replica-b:636"}
	strategy := NewLDAPStrategy(dialer, config, func() any { return &identity.Identity{} })

	_, err := strategy.Authenticate(context.Background(), "alice", "wrong-password")
	if !errors.Is(err, ErrLDAPInvalidCredentials) {
		t.Fatalf("error = %v, want ErrLDAPInvalidCredentials", err)
	}

	if len(dialer.dialed) != 1 {
		t.Errorf("dialled %v; a wrong password was retried against the estate, "+
			"multiplying the deployment lockout counter by the replica count",
			dialer.dialed)
	}
	for _, bind := range secondary.binds {
		if strings.HasPrefix(bind, "uid=alice,") {
			t.Errorf("the second replica saw the user bind %q", bind)
		}
	}
}

// TestLDAPDoesNotRetryAnAnsweredSearch. A directory that answered "no such
// user" has answered. Asking the next replica the same question costs a round
// trip per host on every mistyped username, which is a self-inflicted load
// spike during an outage elsewhere.
func TestLDAPDoesNotRetryAnAnsweredSearch(t *testing.T) {
	dialer := &mockLDAPDialer{perAddr: map[string]*mockLDAPConn{
		"replica-a:636": {entries: nil},
		"replica-b:636": {entries: []LDAPEntry{{DN: "uid=alice,ou=x,dc=example,dc=com"}}},
	}}

	config := defaultLDAPConfig()
	config.Addr = "replica-a:636"
	config.FailoverAddrs = []string{"replica-b:636"}
	strategy := NewLDAPStrategy(dialer, config, func() any { return &identity.Identity{} })

	_, err := strategy.Authenticate(context.Background(), "alice", "password")
	if !errors.Is(err, ErrLDAPUserNotFound) {
		t.Errorf("error = %v, want ErrLDAPUserNotFound", err)
	}
	if len(dialer.dialed) != 1 {
		t.Errorf("dialled %v, want the first answer to be final", dialer.dialed)
	}
}

// TestLDAPExhaustedEstateNamesEveryHost. "connection failed" against a
// three-replica estate does not tell an operator whether one host is down or
// all three, and the two call for very different responses.
func TestLDAPExhaustedEstateNamesEveryHost(t *testing.T) {
	dialer := &mockLDAPDialer{perAddr: map[string]*mockLDAPConn{}}

	config := defaultLDAPConfig()
	config.Addr = "replica-a:636"
	config.FailoverAddrs = []string{"replica-b:636", "replica-c:636"}
	strategy := NewLDAPStrategy(dialer, config, func() any { return &identity.Identity{} })

	_, err := strategy.Authenticate(context.Background(), "alice", "password")
	if !errors.Is(err, ErrLDAPConnectionFailed) {
		t.Fatalf("error = %v, want ErrLDAPConnectionFailed", err)
	}
	for _, addr := range []string{"replica-a:636", "replica-b:636", "replica-c:636"} {
		if !strings.Contains(err.Error(), addr) {
			t.Errorf("error = %v, want it to name %s", err, addr)
		}
	}
	if len(dialer.dialed) != 3 {
		t.Errorf("dialled %v, want every configured host tried", dialer.dialed)
	}
}

// TestLDAPServiceAccountFailureMovesOn. A replica that has not caught up with
// a service-account password rotation is exactly the case failover should
// survive, so it is treated as that host's fault rather than a verdict.
func TestLDAPServiceAccountFailureMovesOn(t *testing.T) {
	stale := &mockLDAPConn{bindErr: map[string]error{
		"cn=svc,dc=example,dc=com": errors.New("service bind rejected")}}
	current := &mockLDAPConn{entries: []LDAPEntry{{DN: "uid=alice,ou=staff,dc=example,dc=com"}}}

	dialer := &mockLDAPDialer{perAddr: map[string]*mockLDAPConn{
		"replica-a:636": stale,
		"replica-b:636": current,
	}}

	config := defaultLDAPConfig()
	config.Addr = "replica-a:636"
	config.FailoverAddrs = []string{"replica-b:636"}
	strategy := NewLDAPStrategy(dialer, config, func() any { return &identity.Identity{} })

	if _, err := strategy.Authenticate(context.Background(), "alice", "password"); err != nil {
		t.Fatalf("Authenticate() error = %v, want the healthy replica to serve it", err)
	}
}

// TestLDAPSearchFailureStillReportsASearchFailure keeps the earlier
// distinction alive through the failover loop. Collapsing an exhausted estate
// into "connection failed" would relabel a wrong base DN -- the operator error
// that looks exactly like an empty directory -- as a network problem.
func TestLDAPSearchFailureStillReportsASearchFailure(t *testing.T) {
	dialer := &mockLDAPDialer{perAddr: map[string]*mockLDAPConn{
		"replica-a:636": {searchErr: errors.New("no such object")},
	}}

	config := defaultLDAPConfig()
	config.Addr = "replica-a:636"
	strategy := NewLDAPStrategy(dialer, config, func() any { return &identity.Identity{} })

	_, err := strategy.Authenticate(context.Background(), "alice", "password")
	if !errors.Is(err, ErrLDAPSearchFailed) {
		t.Errorf("error = %v, want ErrLDAPSearchFailed", err)
	}
	if errors.Is(err, ErrLDAPUserNotFound) {
		t.Error("a failed search was still reported as a missing user")
	}
}

// TestLDAPNoAddressConfiguredSaysSo. Reporting an absent configuration as an
// unreachable directory sends an operator looking at the network.
func TestLDAPNoAddressConfiguredSaysSo(t *testing.T) {
	dialer := &mockLDAPDialer{perAddr: map[string]*mockLDAPConn{}}

	config := defaultLDAPConfig()
	config.Addr = ""
	strategy := NewLDAPStrategy(dialer, config, func() any { return &identity.Identity{} })

	_, err := strategy.Authenticate(context.Background(), "alice", "password")
	if !errors.Is(err, ErrLDAPConnectionFailed) {
		t.Fatalf("error = %v, want ErrLDAPConnectionFailed", err)
	}
	if !strings.Contains(err.Error(), "no directory address is configured") {
		t.Errorf("error = %v, want it to name the missing configuration", err)
	}
	if len(dialer.dialed) != 0 {
		t.Errorf("dialled %v with no address configured", dialer.dialed)
	}
}
