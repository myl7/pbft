// Copyright (c) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

package pkg

import (
	"bytes"
	"encoding/hex"
	"fmt"
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
	N       int
	ID      int
	Seq     int
	View    int
	Privkey []byte
	LogMapSet
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
	rKey := hex.EncodeToString(digestWithDigest)
	h.RequestAcceptMapLock.Lock()
	h.RequestAcceptMap[rKey] = r
	h.RequestAcceptMapLock.Unlock()

	// Gen pre-prepare
	pp := PrePrepare{
		View:   h.View,
		Seq:    h.Seq,
		Digest: digestWithDigest,
	}
	h.Seq++

	// Save pre-prepare
	ppKey := fmt.Sprintf("%d:%d", pp.View, pp.Seq)
	h.PrePrepareAcceptMapLock.Lock()
	h.PrePrepareAcceptMap[ppKey] = pp
	h.PrePrepareAcceptMapLock.Unlock()

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
	key := fmt.Sprintf("%d:%d", pp.View, pp.Seq)
	h.PrePrepareAcceptMapLock.Lock()
	oldPP, ok := h.PrePrepareAcceptMap[key]
	if ok {
		if !bytes.Equal(oldPP.Digest, pp.Digest) {
			log.Printf("error: pre-prepare msg accept conflict: seq = %d\n", pp.Seq)
		}
		return
	}
	h.PrePrepareAcceptMap[key] = pp
	h.PrePrepareAcceptMapLock.Unlock()

	// Save request
	rKey := hex.EncodeToString(pp.Digest)
	h.RequestAcceptMapLock.Lock()
	h.RequestAcceptMap[rKey] = r
	h.RequestAcceptMapLock.Unlock()

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
	pKey := fmt.Sprintf("%d:%d:%s", p.View, p.Seq, hex.EncodeToString(p.Digest))
	h.PrepareAcceptMapLock.Lock()
	counter, ok := h.PrepareAcceptMap[pKey]
	if ok {
		// Exclude duplicate replica
		found := false
		for _, replica := range counter.Replicas {
			if replica == p.Replica {
				found = true
				break
			}
		}

		if !found {
			counter.Replicas = append(counter.Replicas, h.ID)
		}
	} else {
		counter.Replicas = []int{h.ID}
		counter.Data = p
	}
	h.PrepareAcceptMap[pKey] = counter
	h.PrepareAcceptMapLock.Unlock()

	// If prepared
	if len(counter.Replicas) == 2*h.F+1 {
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
	key := fmt.Sprintf("%d:%d:%s", c.View, c.Seq, hex.EncodeToString(c.Digest))
	h.CommitLocalAcceptMapLock.Lock()
	counter, ok := h.CommitLocalAcceptMap[key]
	if ok {
		found := false
		for _, replica := range counter.Replicas {
			if replica == c.Replica {
				found = true
				break
			}
		}
		if !found {
			counter.Replicas = append(counter.Replicas, h.ID)
		}
	} else {
		counter.Replicas = []int{h.ID}
		counter.Data = c
	}
	h.CommitLocalAcceptMap[key] = counter
	h.CommitLocalAcceptMapLock.Unlock()

	// Prepare prepared for checking
	pKey := fmt.Sprintf("%d:%d:%s", c.View, c.Seq, hex.EncodeToString(c.Digest))
	h.PrepareAcceptMapLock.Lock()
	pCounter := h.PrepareAcceptMap[pKey]
	h.PrepareAcceptMapLock.Unlock()

	// If committed-local
	if len(counter.Replicas) == 2*h.F+1 && len(pCounter.Replicas) >= 2*h.F+1 {
		// Fetch request for operation
		h.RequestAcceptMapLock.Lock()
		req, _ := h.RequestAcceptMap[hex.EncodeToString(c.Digest)]
		h.RequestAcceptMapLock.Unlock()

		// Tansform state for state machine
		nextState, res := h.Transform(h.State, req.Op)
		h.State = nextState

		re := Reply{
			View:      c.View,
			Timestamp: req.Timestamp,
			Client:    req.Client,
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

		h.NetReply(req.Client, reSigned)
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

type ReplicaCounter[T Prepare | Commit] struct {
	Data     T
	Replicas []int
}

// Here the log is in the meaning of the paper
type LogMapSet struct {
	// Indexed by client
	LatestTimestampMap     map[string]int64
	LatestTimestampMapLock sync.Mutex
	// Indexed by client
	LastResultMap     map[string]WithSig[Reply]
	LastResultMapLock sync.Mutex
	// Indexed by digest
	RequestAcceptMap     map[string]Request
	RequestAcceptMapLock sync.Mutex
	// Indexed by view + seq
	PrePrepareAcceptMap     map[string]PrePrepare
	PrePrepareAcceptMapLock sync.Mutex
	// Indexed by view + seq + digest so accessible via pre-prepare + request. Used to check prepared
	PrepareAcceptMap     map[string]ReplicaCounter[Prepare]
	PrepareAcceptMapLock sync.Mutex
	// The index and value are the same as PrepareAcceptMap,
	// but in HandleCommit this is used together with PrepareAcceptMap to check committed-local
	CommitLocalAcceptMap     map[string]ReplicaCounter[Commit]
	CommitLocalAcceptMapLock sync.Mutex
}

func NewLogMapSet() *LogMapSet {
	return &LogMapSet{
		LatestTimestampMap:   make(map[string]int64),
		LastResultMap:        make(map[string]WithSig[Reply]),
		RequestAcceptMap:     make(map[string]Request),
		PrePrepareAcceptMap:  make(map[string]PrePrepare),
		PrepareAcceptMap:     make(map[string]ReplicaCounter[Prepare]),
		CommitLocalAcceptMap: make(map[string]ReplicaCounter[Commit]),
	}
}
