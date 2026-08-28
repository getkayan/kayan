package ldapstore

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// startTLSOID is the extended-operation OID that requests the upgrade
// (RFC 4511 section 4.14). Its presence on the wire is what proves the
// upgrade was attempted before anything else was sent.
const startTLSOID = "1.3.6.1.4.1.1466.20037"

// recordingListener accepts one connection, records everything the client
// sends in the clear, and never completes the upgrade.
//
// A directory that refuses StartTLS is the case that matters: the dialer must
// close the connection rather than hand back one a caller would then bind
// over in plaintext.
type recordingListener struct {
	ln       net.Listener
	mu       sync.Mutex
	received []byte
	done     chan struct{}
}

func newRecordingListener(t *testing.T) *recordingListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := &recordingListener{ln: ln, done: make(chan struct{})}

	go func() {
		defer close(r.done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				r.mu.Lock()
				r.received = append(r.received, buf[:n]...)
				r.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	t.Cleanup(func() { _ = ln.Close() })
	return r
}

func (r *recordingListener) addr() string { return r.ln.Addr().String() }

func (r *recordingListener) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, len(r.received))
	copy(out, r.received)
	return out
}

// TestStartTLSIsAttemptedBeforeAnythingElse is the central test.
//
// A directory reached over port 389 is plaintext until StartTLS upgrades it.
// If the dialer returned that connection without upgrading, the caller would
// bind the service account and then the end user over it, putting both
// passwords on the wire in the clear. The bytes the server actually receives
// are the only honest evidence of what was sent.
func TestStartTLSIsAttemptedBeforeAnythingElse(t *testing.T) {
	server := newRecordingListener(t)
	dialer := NewDialer(WithStartTLS(), WithTimeout(2*time.Second))

	conn, err := dialer.DialTLS(context.Background(), server.addr())

	// The listener never completes the upgrade, so the dial must fail.
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("DialTLS succeeded against a server that never completed StartTLS")
	}
	if conn != nil {
		t.Error("DialTLS returned a connection alongside an error; a caller " +
			"checking only the connection would bind over plaintext")
	}

	<-server.done
	sent := string(server.bytes())

	if !strings.Contains(sent, startTLSOID) {
		t.Errorf("the plaintext stream carries no StartTLS request; the connection "+
			"was not upgraded before use. bytes: %q", sent)
	}
}

// TestStartTLSSendsNoCredentialsInTheClear is the property the whole feature
// exists to protect. Whatever else happens, no bind may appear on the
// plaintext leg.
func TestStartTLSSendsNoCredentialsInTheClear(t *testing.T) {
	server := newRecordingListener(t)
	dialer := NewDialer(WithStartTLS(), WithTimeout(2*time.Second))

	conn, err := dialer.DialTLS(context.Background(), server.addr())
	if err == nil && conn != nil {
		// Only reachable if a future change starts returning the un-upgraded
		// connection. Binding here is what a real caller does next.
		_ = conn.Bind("cn=service,dc=example,dc=test", "service-password")
		_ = conn.Close()
	}

	<-server.done
	sent := string(server.bytes())

	for _, secret := range []string{"service-password", "cn=service"} {
		if strings.Contains(sent, secret) {
			t.Errorf("%q appeared on the plaintext leg before the connection was "+
				"encrypted", secret)
		}
	}
}

// TestWithoutStartTLSUsesImplicitLDAPS keeps the default path unchanged. A
// deployment that never asked for StartTLS must still get an implicit TLS
// handshake, not a plaintext connection.
func TestWithoutStartTLSUsesImplicitLDAPS(t *testing.T) {
	server := newRecordingListener(t)
	dialer := NewDialer(WithTimeout(2 * time.Second))

	conn, err := dialer.DialTLS(context.Background(), server.addr())
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("DialTLS succeeded against a listener that speaks no TLS")
	}

	<-server.done
	sent := server.bytes()

	// An implicit-TLS dial opens with a ClientHello: TLS record type 0x16,
	// version 0x03. A StartTLS dial would instead open with an LDAP message.
	if len(sent) > 0 && sent[0] != 0x16 {
		t.Errorf("the default dial did not begin with a TLS ClientHello (first byte %#x); "+
			"it is not using implicit LDAPS", sent[0])
	}
	if strings.Contains(string(sent), startTLSOID) {
		t.Error("the default dial sent a StartTLS request; implicit LDAPS does not use one")
	}
}
