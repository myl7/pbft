package test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/myl7/pbft/pkg"
)

func TestPBFT(t *testing.T) {
	kill := make(chan bool)
	clientChanMap := make([]chan any, 2)
	for i := 0; i < 2; i++ {
		clientChanMap[i] = make(chan any, 100)
	}
	chanMap := make([]chan any, 4)
	for i := 0; i < 4; i++ {
		chanMap[i] = make(chan any, 100)
	}

	nodes := make([]*pkg.Handler, 4)
	for i := 0; i < 4; i++ {
		db, err := sql.Open("sqlite3", ":memory:")
		if err != nil {
			panic(err)
		}

		db.SetMaxOpenConns(1)
		pkg.InitDB(db)

		nodes[i] = &pkg.Handler{
			StateMachine: pkg.StateMachine{
				State: 0,
				Transform: func(state any, op any) (nextState any, res any) {
					return state.(int) + op.(int), state.(int) + op.(int)
				},
			},
			NetFuncSet: pkg.NetFuncSet{
				NetSend: func(id int, msg any) {
					chanMap[id] <- msg
				},
				NetReply: func(client string, msg any) {
					i, _ := strconv.Atoi(client)
					clientChanMap[i] <- msg
				},
				NetBroadcast: func(id int, msg any) {
					for i := 0; i < 4; i++ {
						if i != id {
							chanMap[i] <- msg
						}
					}
				},
			},
			GetPubkeyFuncSet: pkg.GetPubkeyFuncSet{
				GetClientPubkey: func(client string) []byte {
					return nil
				},
				ReplicaPubkeys: make([][]byte, 4),
			},
			DigestFuncSet: pkg.DigestFuncSet{
				Hash: func(data any) []byte {
					b, err := json.Marshal(data)
					if err != nil {
						panic(err)
					}

					digest := sha256.Sum256(b)
					return digest[:]
				},
			},
			PubkeyFuncSet: pkg.PubkeyFuncSet{
				PubkeySign: func(digest []byte, privkey []byte) []byte {
					return nil
				},
				PubkeyVerify: func(sig []byte, digest []byte, pubkey []byte) error {
					return nil
				},
			},
			F:              1,
			N:              4,
			ID:             i,
			Seq:            0,
			View:           0,
			Privkey:        nil,
			LogMapSet:      *pkg.NewLogMapSetDefault(),
			DB:             db,
			DBSerdeFuncSet: *pkg.NewDBSerdeFuncSetDefault(),
		}
	}

	for i := 0; i < 4; i++ {
		go func(i int) {
			for {
				select {
				case msg := <-chanMap[i]:
					switch msg.(type) {
					case pkg.WithSig[pkg.Request]:
						nodes[i].HandleRequest(msg.(pkg.WithSig[pkg.Request]))
					case pkg.PrePrepareMsg:
						nodes[i].HandlePrePrepare(msg.(pkg.PrePrepareMsg))
					case pkg.WithSig[pkg.Prepare]:
						nodes[i].HandlePrepare(msg.(pkg.WithSig[pkg.Prepare]))
					case pkg.WithSig[pkg.Commit]:
						nodes[i].HandleCommit(msg.(pkg.WithSig[pkg.Commit]))
					default:
						panic(fmt.Errorf("Unknown msg type: %T", msg))
					}
				case <-kill:
					return
				}
			}
		}(i)
	}

	rSiged0 := pkg.WithSig[pkg.Request]{
		Body: pkg.Request{
			Op:        1,
			Timestamp: time.Now().UnixNano(),
			Client:    "0",
		},
	}
	chanMap[1] <- rSiged0

	for i := 0; i < 4; i++ {
		select {
		case reply := <-clientChanMap[0]:
			reply0 := reply.(pkg.WithSig[pkg.Reply])
			res := reply0.Body.Result.(int)
			if res != 1 {
				t.Errorf("Expect result = 1 but got %d\n", res)
			}
		case <-kill:
			return
		}
	}

	rSiged1 := pkg.WithSig[pkg.Request]{
		Body: pkg.Request{
			Op:        2,
			Timestamp: time.Now().UnixNano(),
			Client:    "1",
		},
	}
	chanMap[0] <- rSiged1

	for i := 0; i < 4; i++ {
		select {
		case reply := <-clientChanMap[1]:
			reply1 := (reply).(pkg.WithSig[pkg.Reply])
			res := reply1.Body.Result.(int)
			if res != 3 {
				t.Errorf("Expect result = 3 but got %d\n", res)
			}
		case <-kill:
			return
		}
	}

	kill <- true
}
