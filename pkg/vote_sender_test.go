package pkg

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestVotesRecordMessageSender(t *testing.T) {
	for _, phase := range []string{"prepare", "commit"} {
		t.Run(phase, func(t *testing.T) {
			db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "votes.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			InitDB(db)
			h := &Handler{F: 2, ID: 0, DB: db, DBSerdeFuncSet: *NewDBSerdeFuncSetDefault(), DigestFuncSet: *NewDigestFuncSetDefault(), GetPubkeyFuncSet: GetPubkeyFuncSet{ReplicaPubkeys: make([][]byte, 7)}, PubkeyFuncSet: PubkeyFuncSet{PubkeyVerify: func([]byte, []byte, []byte) error { return nil }}}
			h.Init()
			send := func(id int) {
				if phase == "prepare" {
					h.HandlePrepare(WithSig[Prepare]{Body: Prepare{Replica: id, Digest: []byte("request")}})
				} else {
					h.HandleCommit(WithSig[Commit]{Body: Commit{Replica: id, Digest: []byte("request")}})
				}
			}
			// Stay below the four-prepare/five-commit quorum: no asynchronous execution.
			send(1)
			send(1)
			send(1)
			column := "prepare_replicas"
			if phase == "commit" {
				column = "commit_replicas"
			}
			read := func() string {
				var got string
				if err := db.QueryRow("SELECT " + column + " FROM prepares_with_commits").Scan(&got); err != nil {
					t.Fatal(err)
				}
				return got
			}
			if got := read(); got != "1" {
				t.Fatalf("repeated sender recorded as %q, want 1", got)
			}
			send(2)
			send(3)
			if got := read(); got != "1,2,3" {
				t.Fatalf("distinct senders recorded as %q, want 1,2,3", got)
			}
		})
	}
}

func TestVotesKeepRemoteThenSelfOrder(t *testing.T) {
	for _, phase := range []string{"prepare", "commit"} {
		t.Run(phase, func(t *testing.T) {
			db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "votes.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			InitDB(db)
			h := &Handler{F: 2, ID: 0, DB: db, DBSerdeFuncSet: *NewDBSerdeFuncSetDefault(), DigestFuncSet: *NewDigestFuncSetDefault(), GetPubkeyFuncSet: GetPubkeyFuncSet{ReplicaPubkeys: make([][]byte, 7)}, PubkeyFuncSet: PubkeyFuncSet{PubkeyVerify: func([]byte, []byte, []byte) error { return nil }}}
			h.Init()
			for _, id := range []int{1, 0, 2} {
				if phase == "prepare" {
					h.HandlePrepare(WithSig[Prepare]{Body: Prepare{Replica: id, Digest: []byte("request")}})
				} else {
					h.HandleCommit(WithSig[Commit]{Body: Commit{Replica: id, Digest: []byte("request")}})
				}
			}
			column := "prepare_replicas"
			if phase == "commit" {
				column = "commit_replicas"
			}
			var got string
			if err := db.QueryRow("SELECT " + column + " FROM prepares_with_commits").Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != "1,0,2" {
				t.Fatalf("remote/self/remote recorded as %q, want 1,0,2", got)
			}
		})
	}
}
