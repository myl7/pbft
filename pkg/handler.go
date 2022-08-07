// Copyright (c) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

package pkg

import (
	"bytes"
	"database/sql"
	"log"
	"sync"

	"golang.org/x/exp/slices"
)

type Handler struct {
	StateMachine
	NetFuncSet
	GetPubkeyFuncSet
	DigestFuncSet
	PubkeyFuncSet
	// f
	F int
	// Node num in total and should be 3 * F + 1
	N       int
	ID      int
	Seq     int
	View    int
	Privkey []byte
	LogMapSet
	DB *sql.DB
	DBSerdeFuncSet
}

func (h *Handler) HandleRequest(msg WithSig[Request]) {
	r := msg.Body

	// Check if timestamp is later
	h.LatestTimestampMapLock.Lock()
	latestTimestamp, ok := h.LatestTimestampMap[r.Client]
	if ok && r.Timestamp <= latestTimestamp {
		// Notice LatestTimestampMapLock and LastResultMapLock are never both locked
		h.LatestTimestampMapLock.Unlock()
		log.Printf("warning: request timestamp old/repeated: client = %s\n", r.Client)

		// Check if result already exists
		h.LastResultMapLock.Lock()
		lastRe, ok := h.LastResultMap[r.Client]
		if ok && r.Timestamp == lastRe.Body.Timestamp {
			h.LastResultMapLock.Unlock()
			h.NetReply(r.Client, lastRe)
			return
		}
		h.LastResultMapLock.Unlock()
		return
	}
	h.LatestTimestampMap[r.Client] = r.Timestamp
	h.LatestTimestampMapLock.Unlock()

	// Check if sig is valid
	pubkey := h.GetClientPubkey(r.Client)
	digest := h.Hash(r)
	err := h.PubkeyVerify(msg.Sig, digest, pubkey)
	if err != nil {
		log.Printf("error: request sig invalid when handling request: client = %s, err = %s\n", r.Client, err)
		return
	}

	// Check if here is primary
	primary := h.getPrimary()
	if primary != h.ID {
		h.NetSend(primary, msg)
		return
	}

	// Save request
	digestWithDigest := h.Hash(msg)
	h.DB.Exec("INSERT INTO `requests` (`digest`, `request`) VALUES (?, ?)", digestWithDigest, h.DBSer(r))

	// Gen pre-prepare
	pp := PrePrepare{
		View:   h.View,
		Seq:    h.Seq,
		Digest: digestWithDigest,
	}
	h.Seq++

	// Save pre-prepare
	h.DB.Exec("INSERT INTO `pre_prepares` (`view`, `seq`, `pre_prepare`) VALUES (?, ?, ?)", pp.View, pp.Seq, h.DBSer(pp))

	// Send pre-prepare
	ppDigest := h.Hash(pp)
	ppSigned := WithSig[PrePrepare]{
		Body: pp,
		Sig:  h.PubkeySign(ppDigest, h.Privkey),
	}
	ppMsg := PrePrepareMsg{
		PP:  ppSigned,
		Req: msg,
	}
	h.NetBroadcast(h.ID, ppMsg)
}

func (h *Handler) HandlePrePrepare(msg PrePrepareMsg) {
	ppSigned := msg.PP
	pp := ppSigned.Body
	rSigned := msg.Req
	r := rSigned.Body

	// Check if request sig is valid
	clientPubkey := h.GetClientPubkey(r.Client)
	reqDigest := h.Hash(r)
	err := h.PubkeyVerify(rSigned.Sig, reqDigest, clientPubkey)
	if err != nil {
		log.Printf("error: request sig invalid when handling pre-prepare: client = %s, err = %s\n", r.Client, err)
		return
	}

	// Check if sig is valid
	pubkey := h.ReplicaPubkeys[h.getPrimary()]
	digest := h.Hash(pp)
	err = h.PubkeyVerify(ppSigned.Sig, digest, pubkey)
	if err != nil {
		log.Printf("error: pre-prepare sig invalid: seq = %d, err = %s\n", pp.Seq, err)
		return
	}

	// Check if digest matches
	rSignedDigest := h.Hash(rSigned)
	if !bytes.Equal(pp.Digest, rSignedDigest) {
		log.Printf("error: pre-prepare reqDigest invalid: seq = %d\n", pp.Seq)
		return
	}

	// Check if view does not change
	if pp.View != h.View {
		log.Printf("error: pre-prepare view invalid: seq = %d\n", pp.Seq)
		return
	}

	// Check and save pre-prepare
	tx, err := h.DB.Begin()
	if err != nil {
		panic(err)
	}

	rows, err := tx.Query("SELECT `pre_prepare` FROM `pre_prepares` WHERE `view` = ? AND `seq` = ?", pp.View, pp.Seq)
	if err != nil {
		tx.Rollback()
		panic(err)
	}

	if rows.Next() {
		var oldPPB []byte
		err = rows.Scan(&oldPPB)
		if err != nil {
			tx.Rollback()
			panic(err)
		}

		rows.Close()

		var oldPP PrePrepare
		h.DBDe(oldPPB, &oldPP)
		if !bytes.Equal(oldPP.Digest, pp.Digest) {
			log.Printf("error: pre-prepare msg accept conflict: seq = %d\n", pp.Seq)
		}

		tx.Rollback()
		return
	}

	_, err = tx.Exec("INSERT INTO `pre_prepares` (`view`, `seq`, `pre_prepare`) VALUES (?, ?, ?)", pp.View, pp.Seq, h.DBSer(pp))
	if err != nil {
		tx.Rollback()
		panic(err)
	}

	tx.Commit()

	// Save request
	_, err = h.DB.Exec("INSERT INTO `requests` (`digest`, `request`) VALUES (?, ?)", pp.Digest, h.DBSer(r))
	if err != nil {
		panic(err)
	}

	// TODO: Check seq between h and H

	// Gen and send prepare
	p := Prepare{
		View:    pp.View,
		Seq:     pp.Seq,
		Digest:  pp.Digest,
		Replica: h.ID,
	}
	pDigest := h.Hash(p)
	pSigned := WithSig[Prepare]{
		Body: p,
		Sig:  h.PubkeySign(pDigest, h.Privkey),
	}
	// Handle self prepare
	h.HandlePrepare(pSigned)
	h.NetBroadcast(h.ID, pSigned)
}

func (h *Handler) HandlePrepare(msg WithSig[Prepare]) {
	p := msg.Body

	// Check if sig is valid
	pubkey := h.ReplicaPubkeys[p.Replica]
	digest := h.Hash(p)
	err := h.PubkeyVerify(msg.Sig, digest, pubkey)
	if err != nil {
		log.Printf("error: prepare sig invalid: seq = %d, err = %s\n", p.Seq, err)
		return
	}

	// Check if view does not change
	if p.View != h.View {
		log.Printf("error: prepare view invalid: seq = %d\n", p.Seq)
		return
	}

	// TODO: Check seq between h and H

	// Check if prepare is enough
	tx, err := h.DB.Begin()
	if err != nil {
		panic(err)
	}

	rows, err := tx.Query("SELECT `prepare_replicas` FROM `prepares_with_commits` WHERE `view` = ? AND `seq` = ? AND `digest` = ?", p.View, p.Seq, p.Digest)
	if err != nil {
		tx.Rollback()
		panic(err)
	}

	var pReplicas []int
	if rows.Next() {
		var pReplicasS string
		err = rows.Scan(&pReplicasS)
		if err != nil {
			tx.Rollback()
			panic(err)
		}

		rows.Close()

		pReplicas = splitStrToInt(pReplicasS, ",")

		// Exclude duplicate replica
		if slices.Index(pReplicas, p.Replica) == -1 {
			pReplicas = append(pReplicas, h.ID)
			pReplicasS = joinIntToStr(pReplicas, ",")

			_, err = tx.Exec("UPDATE `prepares_with_commits` SET `prepare_replicas` = ? WHERE `view` = ? AND `seq` = ? AND `digest` = ?", pReplicasS, p.View, p.Seq, p.Digest)
			if err != nil {
				tx.Rollback()
				panic(err)
			}
		}
	} else {
		pReplicas = []int{h.ID}
		pReplicaS := joinIntToStr(pReplicas, ",")

		_, err = tx.Exec("INSERT INTO `prepares_with_commits` (`view`, `seq`, `digest`, `prepare`, `prepare_replicas`, `commit`, `commit_replicas`) VALUES (?, ?, ?, ?, ?, ?, ?)", p.View, p.Seq, p.Digest, h.DBSer(p), pReplicaS, "", "")
		if err != nil {
			tx.Rollback()
			panic(err)
		}
	}

	tx.Commit()

	// If prepared
	if len(pReplicas) == 2*h.F+1 {
		// Gen and send commit
		c := Commit{
			View:    p.View,
			Seq:     p.Seq,
			Digest:  p.Digest,
			Replica: h.ID,
		}
		cDigest := h.Hash(c)
		cSigned := WithSig[Commit]{
			Body: c,
			Sig:  h.PubkeySign(cDigest, h.Privkey),
		}
		h.HandleCommit(cSigned)
		h.NetBroadcast(h.ID, cSigned)
	}
}

func (h *Handler) HandleCommit(msg WithSig[Commit]) {
	c := msg.Body

	// Check if sig is valid
	pubkey := h.ReplicaPubkeys[c.Replica]
	digest := h.Hash(c)
	err := h.PubkeyVerify(msg.Sig, digest, pubkey)
	if err != nil {
		log.Printf("error: commit sig invalid: seq = %d, err = %s\n", c.Seq, err)
		return
	}

	// Check if view does not change
	if c.View != h.View {
		log.Printf("error: commit view invalid: seq = %d\n", c.Seq)
		return
	}

	// TODO: Check seq between h and H

	// Check if commit is enough
	tx, err := h.DB.Begin()
	if err != nil {
		panic(err)
	}

	rows, err := tx.Query("SELECT `commit_replicas`, `prepare_replicas` FROM `prepares_with_commits` WHERE `view` = ? AND `seq` = ? AND `digest` = ?", c.View, c.Seq, c.Digest)
	if err != nil {
		tx.Rollback()
		panic(err)
	}

	if !rows.Next() {
		tx.Rollback()
		log.Printf("error: commit not prepared: seq = %d\n", c.Seq)
		return
	}

	var cReplicasS string
	var pReplicasS string
	err = rows.Scan(&cReplicasS, &pReplicasS)
	if err != nil {
		tx.Rollback()
		panic(err)
	}

	rows.Close()

	cReplicas := splitStrToInt(cReplicasS, ",")
	pReplicas := splitStrToInt(pReplicasS, ",")

	if len(pReplicas) < 2*h.F+1 {
		tx.Rollback()
		log.Printf("error: commit not prepared: seq = %d\n", c.Seq)
		return
	}

	if len(cReplicas) == 0 {
		cReplicas = []int{h.ID}
		cReplicasS = joinIntToStr(cReplicas, ",")

		_, err = tx.Exec("UPDATE `prepares_with_commits` SET `commit` = ?, `commit_replicas` = ? WHERE `view` = ? AND `seq` = ? AND `digest` = ?", h.DBSer(c), cReplicasS, c.View, c.Seq, c.Digest)
		if err != nil {
			tx.Rollback()
			panic(err)
		}
	} else {
		if slices.Index(cReplicas, c.Replica) == -1 {
			cReplicas = append(cReplicas, h.ID)
			cReplicasS = joinIntToStr(cReplicas, ",")

			_, err = tx.Exec("UPDATE `prepares_with_commits` SET `commit_replicas` = ? WHERE `view` = ? AND `seq` = ? AND `digest` = ?", cReplicasS, c.View, c.Seq, c.Digest)
			if err != nil {
				tx.Rollback()
				panic(err)
			}
		}
	}

	tx.Commit()

	// If committed-local
	if len(cReplicas) == 2*h.F+1 {
		// Fetch request for operation
		rows, err := h.DB.Query("SELECT `request` FROM `requests` WHERE `digest` = ?", c.Digest)
		if err != nil {
			panic(err)
		}

		if !rows.Next() {
			log.Printf("error: commit request not found: seq = %d\n", c.Seq)
			return
		}

		var rB []byte
		err = rows.Scan(&rB)
		if err != nil {
			panic(err)
		}

		rows.Close()

		var r Request
		h.DBDe(rB, &r)

		// Tansform state for state machine
		nextState, res := h.Transform(h.State, r.Op)
		h.State = nextState

		re := Reply{
			View:      c.View,
			Timestamp: r.Timestamp,
			Client:    r.Client,
			Replica:   h.ID,
			Result:    res,
		}
		reSigned := WithSig[Reply]{
			Body: re,
			Sig:  h.PubkeySign(h.Hash(re), h.Privkey),
		}

		// Cache last result
		h.LastResultMapLock.Lock()
		h.LastResultMap[re.Client] = reSigned
		h.LastResultMapLock.Unlock()

		h.NetReply(r.Client, reSigned)
	}
}

func (h *Handler) getPrimary() int {
	return h.View % h.N
}

type StateMachine struct {
	State     any
	Transform func(state any, op any) (nextState any, res any)
}

type NetFuncSet struct {
	// msg would only be WithSig[Request]
	NetSend func(id int, msg any)
	// msg would only be WithSig[Reply]
	NetReply func(client string, msg any)
	// msg would only be PrePrepareMsg | WithSig[Prepare] | WithSig[Commit]
	NetBroadcast func(id int, msg any)
}

type GetPubkeyFuncSet struct {
	GetClientPubkey func(client string) []byte
	ReplicaPubkeys  [][]byte
}

type DigestFuncSet struct {
	// data would only be Request | WithSig[Request] | PrePrepare | Prepare | Commit | Reply
	Hash func(data any) []byte
}

type PubkeyFuncSet struct {
	PubkeySign   func(digest []byte, privkey []byte) []byte
	PubkeyVerify func(sig []byte, digest []byte, pubkey []byte) error
}

// Here the log is in the meaning of the paper
type LogMapSet struct {
	// Indexed by client
	LatestTimestampMap     map[string]int64
	LatestTimestampMapLock sync.Mutex
	// Indexed by client
	LastResultMap     map[string]WithSig[Reply]
	LastResultMapLock sync.Mutex
}

func NewLogMapSetDefault() *LogMapSet {
	return &LogMapSet{
		LatestTimestampMap: make(map[string]int64),
		LastResultMap:      make(map[string]WithSig[Reply]),
	}
}

type DBSerdeFuncSet struct {
	DBSer func(obj any) (bin []byte)
	DBDe  func(bin []byte, ptr any)
}

func NewDBSerdeFuncSetDefault() *DBSerdeFuncSet {
	return &DBSerdeFuncSet{
		DBSer: GobEnc,
		DBDe:  GobDec,
	}
}
