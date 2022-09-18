// Copyright (c) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

package pkg

import (
	"bytes"
	"database/sql"
	"log"
	"sync"
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
	N        int
	ID       int
	Seq      int
	SeqLock  sync.Mutex
	View     int
	ViewLock sync.RWMutex
	Privkey  []byte
	LogMapSet
	DB *sql.DB
	DBSerdeFuncSet
	requestTableLock          sync.Mutex
	preprepareTableLock       sync.Mutex
	prepareAndCommitTableLock sync.Mutex
	EnableCheckpoint          bool
	HLow                      int
	HHigh                     int
	HLock                     sync.Mutex
	K                         int
	CheckpointSeqInterval     int
	checkCheckpointLock       sync.Mutex
	EnableLogDiscard          bool
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
	h.ViewLock.RLock()
	primary := h.getPrimary()
	if primary != h.ID {
		h.ViewLock.RUnlock()
		h.NetSend(primary, msg)
		return
	}
	h.ViewLock.RUnlock()

	// Gen pre-prepare
	digestWithDigest := h.Hash(msg)
	h.SeqLock.Lock()
	h.ViewLock.RLock()
	pp := PrePrepare{
		View:   h.View,
		Seq:    h.Seq,
		Digest: digestWithDigest,
	}
	h.Seq++
	h.ViewLock.RUnlock()
	h.SeqLock.Unlock()

	// Save request
	h.requestTableLock.Lock()
	_, err = h.DB.Exec("INSERT INTO `requests` (`digest`, `request`, `seq`) VALUES (?, ?, ?)", digestWithDigest, h.DBSer(r), pp.Seq)
	if err != nil {
		h.requestTableLock.Unlock()
		panic(err)
	}
	h.requestTableLock.Unlock()

	// Save pre-prepare
	h.preprepareTableLock.Lock()
	_, err = h.DB.Exec("INSERT INTO `pre_prepares` (`view`, `seq`, `pre_prepare`) VALUES (?, ?, ?)", pp.View, pp.Seq, h.DBSer(pp))
	if err != nil {
		h.preprepareTableLock.Unlock()
		panic(err)
	}
	h.preprepareTableLock.Unlock()

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
	h.ViewLock.RLock()
	pubkey := h.ReplicaPubkeys[h.getPrimary()]
	digest := h.Hash(pp)
	err = h.PubkeyVerify(ppSigned.Sig, digest, pubkey)
	if err != nil {
		h.ViewLock.RUnlock()
		log.Printf("error: pre-prepare sig invalid: seq = %d, err = %s\n", pp.Seq, err)
		return
	}
	h.ViewLock.RUnlock()

	// Check if digest matches
	rSignedDigest := h.Hash(rSigned)
	if !bytes.Equal(pp.Digest, rSignedDigest) {
		log.Printf("error: pre-prepare reqDigest invalid: seq = %d\n", pp.Seq)
		return
	}

	// Check if view does not change
	h.ViewLock.RLock()
	if pp.View != h.View {
		h.ViewLock.RUnlock()
		log.Printf("error: pre-prepare view invalid: seq = %d\n", pp.Seq)
		return
	}
	h.ViewLock.RUnlock()

	// Check seq between h and H
	if h.EnableCheckpoint {
		h.HLock.Lock()
		if pp.Seq < h.HLow || pp.Seq > h.HHigh {
			h.HLock.Unlock()
			log.Printf("error: pre-prepare seq not in [h, H]: seq = %d\n", pp.Seq)
			return
		}
		h.HLock.Unlock()
	}

	// Check and save pre-prepare
	h.preprepareTableLock.Lock()

	rows, err := h.DB.Query("SELECT `pre_prepare` FROM `pre_prepares` WHERE `view` = ? AND `seq` = ?", pp.View, pp.Seq)
	if err != nil {
		h.preprepareTableLock.Unlock()
		panic(err)
	}

	if rows.Next() {
		var oldPPB []byte
		err = rows.Scan(&oldPPB)
		if err != nil {
			h.preprepareTableLock.Unlock()
			panic(err)
		}

		rows.Close()

		var oldPP PrePrepare
		h.DBDe(oldPPB, &oldPP)
		if !bytes.Equal(oldPP.Digest, pp.Digest) {
			log.Printf("error: pre-prepare msg accept conflict: seq = %d\n", pp.Seq)
		}

		h.preprepareTableLock.Unlock()
		return
	}

	_, err = h.DB.Exec("INSERT INTO `pre_prepares` (`view`, `seq`, `pre_prepare`) VALUES (?, ?, ?)", pp.View, pp.Seq, h.DBSer(pp))
	if err != nil {
		h.preprepareTableLock.Unlock()
		panic(err)
	}

	h.preprepareTableLock.Unlock()

	// Save request
	h.requestTableLock.Lock()
	_, err = h.DB.Exec("INSERT INTO `requests` (`digest`, `request`, `seq`) VALUES (?, ?, ?)", pp.Digest, h.DBSer(r), pp.Seq)
	if err != nil {
		h.requestTableLock.Unlock()
		panic(err)
	}
	h.requestTableLock.Unlock()

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
	go h.HandlePrepare(pSigned)
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
	h.ViewLock.RLock()
	if p.View != h.View {
		h.ViewLock.RUnlock()
		log.Printf("error: prepare view invalid: seq = %d\n", p.Seq)
		return
	}
	h.ViewLock.RUnlock()

	// Check seq between h and H
	if h.EnableCheckpoint {
		h.HLock.Lock()
		if p.Seq < h.HLow || p.Seq > h.HHigh {
			h.HLock.Unlock()
			log.Printf("error: prepare seq not in [h, H]: seq = %d\n", p.Seq)
			return
		}
		h.HLock.Unlock()
	}

	// Check if prepare is enough
	h.prepareAndCommitTableLock.Lock()
	defer h.prepareAndCommitTableLock.Unlock()

	rows, err := h.DB.Query("SELECT `prepare_replicas`, `prepared`, `commit`, `commit_replicas`, `committed_local` FROM `prepares_with_commits` WHERE `view` = ? AND `seq` = ? AND `digest` = ?", p.View, p.Seq, p.Digest)
	if err != nil {
		panic(err)
	}

	var pReplicas []int
	var prepared int
	var cReplicas []int
	var cB []byte
	var committedLocal int
	if rows.Next() {
		var pReplicasS string
		var cReplicasS string
		err = rows.Scan(&pReplicasS, &prepared, &cB, &cReplicasS, &committedLocal)
		if err != nil {
			panic(err)
		}

		rows.Close()

		pReplicas = splitStrToInt(pReplicasS, ",")
		cReplicas = splitStrToInt(cReplicasS, ",")

		// Exclude duplicate replica
		if indexOf(pReplicas, p.Replica) == -1 {
			pReplicas = append(pReplicas, h.ID)
			pReplicasS = joinIntToStr(pReplicas, ",")

			_, err = h.DB.Exec("UPDATE `prepares_with_commits` SET `prepare_replicas` = ? WHERE `view` = ? AND `seq` = ? AND `digest` = ?", pReplicasS, p.View, p.Seq, p.Digest)
			if err != nil {
				panic(err)
			}
		}
	} else {
		pReplicas = []int{h.ID}
		pReplicaS := joinIntToStr(pReplicas, ",")

		_, err = h.DB.Exec("INSERT INTO `prepares_with_commits` (`view`, `seq`, `digest`, `prepare`, `prepare_replicas`, `prepared`, `commit`, `commit_replicas`, `committed_local`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", p.View, p.Seq, p.Digest, h.DBSer(p), pReplicaS, 0, "", "", 0)
		if err != nil {
			panic(err)
		}
	}

	// If prepared
	if len(pReplicas) >= 2*h.F && prepared == 0 {
		_, err = h.DB.Exec("UPDATE `prepares_with_commits` SET `prepared` = 1 WHERE `view` = ? AND `seq` = ? AND `digest` = ?", p.View, p.Seq, p.Digest)
		if err != nil {
			panic(err)
		}

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
		go h.HandleCommit(cSigned)
		go h.NetBroadcast(h.ID, cSigned)
	}

	// If committed-local
	if len(cReplicas) >= 2*h.F+1 && committedLocal == 0 && len(pReplicas) >= 2*h.F {
		_, err = h.DB.Exec("UPDATE `prepares_with_commits` SET `committed_local` = 1 WHERE `view` = ? AND `seq` = ? AND `digest` = ?", p.View, p.Seq, p.Digest)
		if err != nil {
			panic(err)
		}

		var c Commit
		h.DBDe(cB, &c)
		go h.OnCommittedLocal(c)
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
	h.ViewLock.RLock()
	if c.View != h.View {
		h.ViewLock.RUnlock()
		log.Printf("error: commit view invalid: seq = %d\n", c.Seq)
		return
	}
	h.ViewLock.RUnlock()

	// Check seq between h and H
	if h.EnableCheckpoint {
		h.HLock.Lock()
		if c.Seq < h.HLow || c.Seq > h.HHigh {
			h.HLock.Unlock()
			log.Printf("error: commit seq not in [h, H]: seq = %d\n", c.Seq)
			return
		}
		h.HLock.Unlock()
	}

	// Check if commit is enough
	h.prepareAndCommitTableLock.Lock()
	defer h.prepareAndCommitTableLock.Unlock()

	rows, err := h.DB.Query("SELECT `commit_replicas`, `committed_local`, `prepared` FROM `prepares_with_commits` WHERE `view` = ? AND `seq` = ? AND `digest` = ?", c.View, c.Seq, c.Digest)
	if err != nil {
		panic(err)
	}

	var cReplicasS string
	var committedLocal int
	var prepared int
	if rows.Next() {
		err = rows.Scan(&cReplicasS, &committedLocal, &prepared)
		if err != nil {
			panic(err)
		}

		rows.Close()
	} else {
		log.Printf("warning: commit no prepare: seq = %d\n", c.Seq)

		_, err := h.DB.Exec("INSERT INTO `prepares_with_commits` (`view`, `seq`, `digest`, `prepare`, `prepare_replicas`, `prepared`, `commit`, `commit_replicas`, `committed_local`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", c.View, c.Seq, c.Digest, "", "", 0, h.DBSer(c), "", 0)
		if err != nil {
			panic(err)
		}

		cReplicasS = ""
		committedLocal = 0
		prepared = 0
	}

	cReplicas := splitStrToInt(cReplicasS, ",")

	if len(cReplicas) == 0 {
		cReplicas = []int{h.ID}
		cReplicasS = joinIntToStr(cReplicas, ",")

		_, err = h.DB.Exec("UPDATE `prepares_with_commits` SET `commit` = ?, `commit_replicas` = ? WHERE `view` = ? AND `seq` = ? AND `digest` = ?", h.DBSer(c), cReplicasS, c.View, c.Seq, c.Digest)
		if err != nil {
			panic(err)
		}
	} else {
		if indexOf(cReplicas, c.Replica) == -1 {
			cReplicas = append(cReplicas, h.ID)
			cReplicasS = joinIntToStr(cReplicas, ",")

			_, err = h.DB.Exec("UPDATE `prepares_with_commits` SET `commit_replicas` = ? WHERE `view` = ? AND `seq` = ? AND `digest` = ?", cReplicasS, c.View, c.Seq, c.Digest)
			if err != nil {
				panic(err)
			}
		}
	}

	// If committed-local
	if len(cReplicas) >= 2*h.F+1 && committedLocal == 0 && prepared > 0 {
		_, err = h.DB.Exec("UPDATE `prepares_with_commits` SET `committed_local` = 1 WHERE `view` = ? AND `seq` = ? AND `digest` = ?", c.View, c.Seq, c.Digest)
		if err != nil {
			panic(err)
		}

		go h.OnCommittedLocal(c)
	}
}

func (h *Handler) OnCommittedLocal(c Commit) {
	// Fetch request for operation
	h.requestTableLock.Lock()
	rows, err := h.DB.Query("SELECT `request` FROM `requests` WHERE `digest` = ?", c.Digest)
	if err != nil {
		h.requestTableLock.Unlock()
		panic(err)
	}

	if !rows.Next() {
		log.Printf("error: commit request not found: seq = %d\n", c.Seq)
		h.requestTableLock.Unlock()
		return
	}

	var rB []byte
	err = rows.Scan(&rB)
	if err != nil {
		h.requestTableLock.Unlock()
		panic(err)
	}

	rows.Close()
	h.requestTableLock.Unlock()

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

	if h.EnableCheckpoint && c.Seq != 0 && c.Seq%h.CheckpointSeqInterval == 0 {
		ch := Checkpoint{
			Seq:         c.Seq,
			StateDigest: h.Hash(h.State),
			Replica:     h.ID,
		}
		go h.OnCheckpoint(ch)
	}

	h.NetReply(r.Client, reSigned)
}

func (h *Handler) HandleCheckpoint(msg WithSig[Checkpoint]) {
	ch := msg.Body

	// Check if sig is valid
	pubkey := h.ReplicaPubkeys[ch.Replica]
	digest := h.Hash(ch)
	err := h.PubkeyVerify(msg.Sig, digest, pubkey)
	if err != nil {
		log.Printf("error: checkpoint sig invalid: seq = %d, err = %s\n", ch.Seq, err)
		return
	}

	h.checkCheckpointLock.Lock()
	defer h.checkCheckpointLock.Unlock()

	tx, err := h.DB.Begin()
	if err != nil {
		panic(err)
	}

	rows, err := h.DB.Query("SELECT `replicas`, `stable` FROM `checkpoints` WHERE `seq` = ? AND `state_digest` = ?", ch.Seq, ch.StateDigest)
	if err != nil {
		tx.Rollback()
		panic(err)
	}

	var replicas []int
	var stable int
	if rows.Next() {
		var replicasS string
		err = rows.Scan(&replicasS, &stable)
		if err != nil {
			tx.Rollback()
			panic(err)
		}

		replicas = splitStrToInt(replicasS, ",")

		if indexOf(replicas, ch.Replica) == -1 {
			replicas = append(replicas, ch.Replica)
			replicasS = joinIntToStr(replicas, ",")

			_, err = tx.Exec("UPDATE `checkpoints` SET `replicas` = ? WHERE `seq` = ? AND `state_digest` = ?", replicasS, ch.Seq, ch.StateDigest)
			if err != nil {
				tx.Rollback()
				panic(err)
			}
		}
	} else {
		replicas = []int{ch.Replica}
		_, err := h.DB.Exec("INSERT INTO `checkpoints` (`seq`, `state_digest`, `replicas`, `stable`) VALUES (?, ?, ?, ?)", ch.Seq, ch.StateDigest, "", 0)
		if err != nil {
			tx.Rollback()
			panic(err)
		}
	}

	if len(replicas) >= 2*h.F+1 && stable == 0 {
		_, err = tx.Exec("UPDATE `checkpoints` SET `stable` = 1 WHERE `seq` = ? AND `state_digest` = ?", ch.Seq, ch.StateDigest)
		if err != nil {
			tx.Rollback()
			panic(err)
		}

		go h.OnCheckpointStable(ch)
	}

	tx.Commit()
}

func (h *Handler) OnCheckpointStable(ch Checkpoint) {
	h.HLock.Lock()
	h.HLow = ch.Seq
	h.HHigh = ch.Seq + h.K
	h.HLock.Unlock()

	if h.EnableLogDiscard {
		h.requestTableLock.Lock()
		_, err := h.DB.Exec("DELETE FROM `requests` WHERE `seq` < ?", ch.Seq)
		if err != nil {
			h.requestTableLock.Unlock()
			panic(err)
		}
		h.requestTableLock.Unlock()

		h.preprepareTableLock.Lock()
		_, err = h.DB.Exec("DELETE FROM `pre_prepares` WHERE `seq` < ?", ch.Seq)
		if err != nil {
			h.checkCheckpointLock.Unlock()
			panic(err)
		}
		h.checkCheckpointLock.Unlock()

		h.prepareAndCommitTableLock.Lock()
		_, err = h.DB.Exec("DELETE FROM `prepares_with_commits` WHERE `seq` < ?", ch.Seq)
		if err != nil {
			h.prepareAndCommitTableLock.Unlock()
			panic(err)
		}
		h.prepareAndCommitTableLock.Unlock()
	}
}

func (h *Handler) OnCheckpoint(ch Checkpoint) {
	chSigned := WithSig[Checkpoint]{
		Body: ch,
		Sig:  h.PubkeySign(h.Hash(ch), h.Privkey),
	}
	h.NetBroadcast(h.ID, chSigned)
}

// Remember to lock ViewLock before calling
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

type DBSerdeFuncSet struct {
	DBSer func(obj any) (bin []byte)
	DBDe  func(bin []byte, ptr any)
}

func (h *Handler) Init() {
	h.LatestTimestampMap = make(map[string]int64)
	h.LastResultMap = make(map[string]WithSig[Reply])
	h.N = 3*h.F + 1
	h.HLow = h.Seq
	h.HHigh = h.HLow + h.K
}
