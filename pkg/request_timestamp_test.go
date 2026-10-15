package pkg

import (
	"errors"
	"sync/atomic"
	"testing"
)

func timestampTestHandler(verify func([]byte, []byte, []byte) error, send func(int, any)) *Handler {
	h := &Handler{F: 1, ID: 1,
		GetPubkeyFuncSet: GetPubkeyFuncSet{GetClientPubkey: func(string) []byte { return nil }},
		DigestFuncSet:    DigestFuncSet{Hash: func(any) []byte { return nil }},
		PubkeyFuncSet:    PubkeyFuncSet{PubkeyVerify: verify},
		NetFuncSet:       NetFuncSet{NetSend: send},
	}
	h.Init()
	return h
}

func TestRequestInvalidSignatureKeepsTimestamp(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "new-client"
		if existing {
			name = "existing-client"
		}
		t.Run(name, func(t *testing.T) {
			var forwards, verifies int
			h := timestampTestHandler(func(sig, _, _ []byte) error {
				verifies++
				if len(sig) == 0 {
					return errors.New("invalid signature")
				}
				return nil
			}, func(int, any) { forwards++ })
			if existing {
				h.LatestTimestampMap["client"] = 5
			}
			h.HandleRequest(WithSig[Request]{Body: Request{Client: "client", Timestamp: 1 << 62}})
			got, ok := h.LatestTimestampMap["client"]
			if (existing && (!ok || got != 5)) || (!existing && ok) {
				t.Fatalf("invalid signature changed timestamp: value=%d present=%v", got, ok)
			}
			h.HandleRequest(WithSig[Request]{Body: Request{Client: "client", Timestamp: 10}, Sig: []byte{1}})
			if forwards != 1 || verifies != 2 || h.LatestTimestampMap["client"] != 10 {
				t.Fatalf("valid request blocked: forwards=%d verifies=%d timestamp=%d", forwards, verifies, h.LatestTimestampMap["client"])
			}
		})
	}
}

func TestRequestDuplicateKeepsCachedReplyFastPath(t *testing.T) {
	var verifies, forwards, replies int
	h := timestampTestHandler(func(_, _, _ []byte) error { verifies++; return nil }, func(int, any) { forwards++ })
	msg := WithSig[Request]{Body: Request{Client: "client", Timestamp: 10}}
	h.HandleRequest(msg)
	cached := WithSig[Reply]{Body: Reply{Client: "client", Timestamp: 10, Result: 42}}
	h.LastResultMap["client"] = cached
	h.NetReply = func(client string, reply any) {
		replies++
		got := reply.(WithSig[Reply])
		if client != "client" || got.Body.Timestamp != 10 || got.Body.Result != 42 {
			t.Errorf("cached reply changed: %v", got)
		}
	}
	h.HandleRequest(msg)
	if verifies != 1 || forwards != 1 || replies != 1 {
		t.Fatalf("duplicate path changed: verifies=%d forwards=%d replies=%d", verifies, forwards, replies)
	}
}

func TestRequestTimestampRecheckedAfterVerification(t *testing.T) {
	for _, next := range []int64{10, 20} {
		name := "duplicate"
		if next == 20 {
			name = "newer"
		}
		t.Run(name, func(t *testing.T) {
			verifying, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var forwards int32
			h := timestampTestHandler(func(sig, _, _ []byte) error {
				if sig[0] == 1 {
					close(verifying)
					<-release
				}
				return nil
			}, func(int, any) { atomic.AddInt32(&forwards, 1) })
			go func() {
				defer close(done)
				h.HandleRequest(WithSig[Request]{Body: Request{Client: "client", Timestamp: 10}, Sig: []byte{1}})
			}()
			<-verifying
			h.HandleRequest(WithSig[Request]{Body: Request{Client: "client", Timestamp: next}, Sig: []byte{2}})
			close(release)
			<-done
			if got := h.LatestTimestampMap["client"]; got != next {
				t.Fatalf("timestamp rolled back: got %d want %d", got, next)
			}
			if got := atomic.LoadInt32(&forwards); got != 1 {
				t.Fatalf("forwarded %d requests, want 1", got)
			}
		})
	}
}

// Isolate timestamp bookkeeping: RSA and network costs are deliberately excluded.
func BenchmarkRequestTimestampBookkeeping(b *testing.B) {
	h := timestampTestHandler(func(_, _, _ []byte) error { return nil }, func(int, any) {})
	msg := WithSig[Request]{Body: Request{Client: "client"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg.Body.Timestamp = int64(i)
		h.HandleRequest(msg)
	}
}
