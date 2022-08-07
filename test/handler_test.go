package test

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"fmt"
	"strconv"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/myl7/pbft/pkg"
)

func TestPBFT(t *testing.T) {
	F := 1
	N := 3*F + 1
	CN := 2

	kill := make(chan bool)
	clientChanMap := make([]chan any, CN)
	for i := 0; i < CN; i++ {
		clientChanMap[i] = make(chan any, 100)
	}
	chanMap := make([]chan any, N)
	for i := 0; i < N; i++ {
		chanMap[i] = make(chan any, 100)
	}

	privkeys := make([][]byte, N+CN)
	pubkeys := make([][]byte, N+CN)
	for i := 0; i < N+CN; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			panic(err)
		}

		privkeys[i] = pkg.SerRSAPrivkey(key)
		pubkeys[i] = pkg.SerRSAPubkey(&key.PublicKey)
	}

	nodes := make([]*pkg.Handler, N)
	for i := 0; i < N; i++ {
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
					for i := 0; i < N; i++ {
						if i != id {
							chanMap[i] <- msg
						}
					}
				},
			},
			GetPubkeyFuncSet: pkg.GetPubkeyFuncSet{
				GetClientPubkey: func(client string) []byte {
					i, err := strconv.Atoi(client)
					if err != nil {
						panic(err)
					}

					return pubkeys[i+N]
				},
				ReplicaPubkeys: pubkeys,
			},
			DigestFuncSet:  *pkg.NewDigestFuncSetDefault(),
			PubkeyFuncSet:  *pkg.NewPubkeyFuncSetDefault(),
			F:              1,
			ID:             i,
			Privkey:        privkeys[i],
			DB:             db,
			DBSerdeFuncSet: *pkg.NewDBSerdeFuncSetDefault(),
		}
		nodes[i].Init()
	}

	for i := 0; i < N; i++ {
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
	rSiged0.Sig = pkg.RSAWithSHA3512Sign(pkg.SHA3WithGobHash(rSiged0.Body), privkeys[N+0])
	chanMap[1] <- rSiged0

	for i := 0; i < N; i++ {
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
	rSiged1.Sig = pkg.RSAWithSHA3512Sign(pkg.SHA3WithGobHash(rSiged1.Body), privkeys[N+1])
	chanMap[0] <- rSiged1

	for i := 0; i < N; i++ {
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
