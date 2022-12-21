package pbft

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/myl7/pbft/test"
	"google.golang.org/protobuf/proto"
)

func TestNodeCluster(t *testing.T) {
	f := 1
	n := 3*f + 1
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		ids[i] = testGenS(t, 32)
	}
	kps := test.LoadTestKPs(t)
	pks := make(map[string][]byte)
	for i := 0; i < n; i++ {
		pks[ids[i]] = kps[i].PK
	}
	partialNP := NodeParams{
		N:   n,
		PKs: pks,
	}
	ndChans := make(map[string]chan chanNCMsg, n)
	for i := 0; i < n; i++ {
		ndChans[ids[i]] = make(chan chanNCMsg, 100)
	}
	uChan := make(chan chanNCMsg, 100)
	user := testGenS(t, 32)
	uKP := kps[n]
	uPK := uKP.PK
	uSK := uKP.SK

	nds := make([]*Node, n)
	for i := 0; i < n; i++ {
		// PKs is only read, so safe to share it
		np := partialNP
		np.ID = ids[i]
		np.SK = kps[i].SK
		nc := newChanNodeCommunicator(ndChans, uChan)
		ns := newMemMapNodeStorage()
		nsm := newTestNodeStateMachine()
		nupg := newTestNodeUserPKGetter(map[string][]byte{user: uPK})
		npg := newTestNodePrimaryGetter(ids[0])
		nds[i] = NewNode(np, nc, ns, nsm, nupg, npg)
	}

	errChan := make(chan error)
	errMetaChan := make(chan string)
	for i := 0; i < n; i++ {
		nd := nds[i]
		go func(i int) {
			for {
				chanMsg := <-ndChans[nd.np.ID]
				switch chanMsg.msgType {
				case msgTypeRequest:
					err := nd.HandleRequest(chanMsg.b)
					if err != nil {
						errChan <- err
						errMetaChan <- fmt.Sprintf("node %d HandleRequest error", i)
						return
					}
				case msgTypePrePrepare:
					ppWithReq := make(map[string][]byte)
					err := json.Unmarshal(chanMsg.b, &ppWithReq)
					if err != nil {
						// Should never happen since the test handles the serde
						panic(err)
					}

					err = nd.HandlePrePrepare(ppWithReq["pp"], ppWithReq["req"])
					if err != nil {
						errChan <- err
						errMetaChan <- fmt.Sprintf("node %d HandlePreprepare error", i)
						return
					}
				case msgTypePrepare:
					err := nd.HandlePrepare(chanMsg.b)
					if err != nil {
						errChan <- err
						errMetaChan <- fmt.Sprintf("node %d HandlePrepare error", i)
						return
					}
				case msgTypeCommit:
					err := nd.HandleCommit(chanMsg.b)
					if err != nil {
						errChan <- err
						errMetaChan <- fmt.Sprintf("node %d HandleCommit error", i)
						return
					}
				}
			}
		}(i)
	}

	reqB, req := testGenReq(t, user, uSK)

	err := nds[0].HandleRequest(reqB)
	if err != nil {
		t.Fatal(err)
	}

	resultReceived := make(map[string]bool, n)
	resultView := int32(-1)
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		func() {
			defer cancel()
			select {
			case retChanMsg := <-uChan:
				if retChanMsg.user != user {
					t.Fatalf("result user unmatches: %s != %s", retChanMsg.user, user)
				}
				rep := &Reply{}
				err := proto.Unmarshal(retChanMsg.b, rep)
				if err != nil {
					t.Fatal(err)
				}

				// Skip sig check since there are no malicious nodes in the test
				if resultView == -1 {
					resultView = rep.View
				} else if rep.View != resultView {
					t.Fatalf("result view unmatches: %d != %d", rep.View, resultView)
				}
				if rep.Timestamp != req.Timestamp {
					t.Fatalf("result timestamp unmatches: %d != %d", rep.Timestamp, req.Timestamp)
				}
				if rep.User != user {
					t.Fatalf("result user unmatches: %s != %s", rep.User, user)
				}
				if resultReceived[rep.Node] {
					t.Fatalf("duplicate result from node %s", rep.Node)
				} else {
					resultReceived[rep.Node] = true
				}
				if !bytes.Equal(rep.Result, req.Op) {
					t.Fatalf("result result unmatches: %x != %x", rep.Result, req.Op)
				}
			case <-ctx.Done():
				t.Fatalf("timeout when waiting enough results: got %d", i)
			case err := <-errChan:
				errMeta := <-errMetaChan
				t.Fatalf("%s: %s", errMeta, err)
			}
		}()
	}
}

func testGenReq(t *testing.T, user string, uSK []byte) ([]byte, *Request) {
	timestamp := time.Now().UnixNano()
	op := testGenB(t, 32)

	req := &Request{
		Op:        op,
		Timestamp: timestamp,
		User:      user,
	}
	reqSigDigest := hashMsgWithoutSig(req)
	reqSig := genSig(reqSigDigest, uSK)
	req.Sig = reqSig
	reqB, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	return reqB, req
}

func testGenB(t *testing.T, len int) []byte {
	b := make([]byte, len)
	_, err := rand.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testGenS(t *testing.T, bLen int) string {
	b := testGenB(t, bLen)
	return hex.EncodeToString(b)
}

// Test-purposed trait impl

type memMapNodeStorage struct {
	s map[string][]byte
}

func newMemMapNodeStorage() *memMapNodeStorage {
	return &memMapNodeStorage{
		s: make(map[string][]byte),
	}
}

func (ns *memMapNodeStorage) Get(key string) ([]byte, error) {
	return ns.s[key], nil
}

func (ns *memMapNodeStorage) Put(key string, val []byte) error {
	ns.s[key] = val
	return nil
}

type chanNodeCommunicator struct {
	nodeChans map[string]chan chanNCMsg
	userChan  chan chanNCMsg
}

type chanNCMsg struct {
	b       []byte
	msgType msgType
	// user If set, the msg is a reply and sent to this user
	user string
}

func newChanNodeCommunicator(nodeChans map[string]chan chanNCMsg, userChan chan chanNCMsg) *chanNodeCommunicator {
	return &chanNodeCommunicator{
		nodeChans: nodeChans,
		userChan:  userChan,
	}
}

func (nc *chanNodeCommunicator) Unicast(msgB []byte, toNode string, msgTyp msgType) error {
	nc.delay()
	nc.nodeChans[toNode] <- chanNCMsg{
		b:       msgB,
		msgType: msgTyp,
	}
	return nil
}

func (nc *chanNodeCommunicator) Broadcast(msgB []byte, fromNode string, msgTyp msgType) error {
	for toNode, ch := range nc.nodeChans {
		if toNode == fromNode {
			continue
		}
		go func(ch chan chanNCMsg) {
			nc.delay()
			ch <- chanNCMsg{
				b:       msgB,
				msgType: msgTyp,
			}
		}(ch)
	}
	return nil
}

func (nc *chanNodeCommunicator) BroadcastWithLarge(msgB []byte, msgLB []byte, fromNode string, msgTyp msgType) error {
	ppWithReq := map[string][]byte{
		"pp":  msgB,
		"req": msgLB,
	}
	ppWithReqB, err := json.Marshal(ppWithReq)
	if err != nil {
		return err
	}
	return nc.Broadcast(ppWithReqB, fromNode, msgTyp)
}

func (nc *chanNodeCommunicator) Return(msgB []byte, toUser string) error {
	nc.delay()
	nc.userChan <- chanNCMsg{
		b:       msgB,
		msgType: msgTypeReply,
		user:    toUser,
	}
	return nil
}

// delay is used to simulate actual network delay
func (nc *chanNodeCommunicator) delay() {
	time.Sleep(time.Millisecond * time.Duration(mrand.Intn(100)+100))
}

type testNodeStateMachine struct {
	ops [][]byte
}

func newTestNodeStateMachine() *testNodeStateMachine {
	return &testNodeStateMachine{
		ops: make([][]byte, 0),
	}
}

func (nsm *testNodeStateMachine) Transform(op []byte) []byte {
	nsm.ops = append(nsm.ops, op)
	return op
}

type testNodeUserPKGetter struct {
	pks map[string][]byte
}

func newTestNodeUserPKGetter(pks map[string][]byte) *testNodeUserPKGetter {
	return &testNodeUserPKGetter{
		pks: pks,
	}
}

func (nupkg *testNodeUserPKGetter) Get(user string) ([]byte, error) {
	return nupkg.pks[user], nil
}

type testNodePrimaryGetter struct {
	primary string
}

func newTestNodePrimaryGetter(primary string) *testNodePrimaryGetter {
	return &testNodePrimaryGetter{
		primary: primary,
	}
}

func (npg *testNodePrimaryGetter) Get(view int) (string, error) {
	return npg.primary, nil
}
