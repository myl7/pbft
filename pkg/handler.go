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
	privkey []byte
	// Indexed by client
	LatestTimestampMap     map[string]int64
	LatestTimestampMapLock sync.Mutex
	// Indexed by timestamp
	LastResultMap     map[string]*Reply
	LastResultMapLock sync.Mutex
	// Indexed by req digest. Basically only for req storage. Sig in req is trimmed.
	RequestAcceptMap     map[string]*Request
	RequestAcceptMapLock sync.Mutex
	// Indexed by view + seq. The value is req digest.
	PrePrepareAcceptMap     map[string][]byte
	PrePrepareAcceptMapLock sync.Mutex
	// Indexed by view + seq + req digest so accessible via pre-prepare + request. The value is accepted num.
	PrepareAcceptMap     map[string][]int
	PrepareAcceptMapLock sync.Mutex
	// The index and value are the same as PrepareAcceptMap,
	// but in HandleCommit this is used with together with PrepareAcceptMap to check committed and committed-local
	CommitLocalAcceptMap     map[string][]int
	CommitLocalAcceptMapLock sync.Mutex
}

// ser will be used to set hash func that is related with sign/verify func
func (h *Handler) SetDefault(ser func(data any) (bin []byte)) *Handler {
	h.LatestTimestampMap = make(map[string]int64)
	h.LastResultMap = make(map[string]*Reply)
	h.RequestAcceptMap = make(map[string]*Request)
	h.PrePrepareAcceptMap = make(map[string][]byte)
	h.PrepareAcceptMap = make(map[string][]int)
	h.CommitLocalAcceptMap = make(map[string][]int)
	h.Hash = GenSHA256Hash(ser)
	h.PubkeySign = RSAAndSHA256PubkeySign
	h.PubkeyVerify = RSAAndSHA256PubkeyVerify
	return h
}

func (h *Handler) HandleRequest(msg *Request) {
	// Check if timestamp is later
	h.LatestTimestampMapLock.Lock()
	latestTimestamp, ok := h.LatestTimestampMap[msg.Client]
	if ok && msg.Timestamp <= latestTimestamp {
		h.LatestTimestampMapLock.Unlock()
		log.Printf("warning: request timestamp old/repeated: client = %s\n", msg.Client)
		return
	}
	h.LatestTimestampMap[msg.Client] = msg.Timestamp
	h.LatestTimestampMapLock.Unlock()

	// Check if result already exists
	h.LastResultMapLock.Lock()
	lastResult, ok := h.LastResultMap[msg.Client]
	if ok && msg.Timestamp == lastResult.Timestamp {
		h.LastResultMapLock.Unlock()
		h.NetReply(msg.Client, lastResult)
		return
	}
	h.LastResultMapLock.Unlock()

	// Check if sig is valid
	pubkey := h.GetClientPubkey(msg.Client)
	sig := msg.Sig
	// Temporarily reset sig for hashing
	msg.Sig = nil
	digest := h.Hash(msg)
	err := h.PubkeyVerify(sig, digest, pubkey)
	if err != nil {
		log.Printf("error: request sig invalid when handling request: client = %s, err = %s\n", msg.Client, err)
		return
	}
	// Recover sig
	msg.Sig = sig

	// Check if here is primary
	primary := h.getPrimary()
	if primary != h.ID {
		h.NetSend(primary, msg)
		return
	}

	// Save request
	digestWithDigest := h.Hash(msg)
	rKey := hex.EncodeToString(digestWithDigest)
	newReq := *msg
	newReq.Sig = nil
	h.RequestAcceptMapLock.Lock()
	h.RequestAcceptMap[rKey] = &newReq
	h.RequestAcceptMapLock.Unlock()

	// Gen and send pre-prepare
	pp := &PrePrepare{
		View:   h.View,
		Seq:    h.Seq,
		Digest: digestWithDigest,
	}
	ppDigest := h.Hash(pp)
	pp.Sig = h.PubkeySign(ppDigest, h.privkey)
	ppMsg := &PrePrepareMsg{
		PrePrepare: *pp,
		Req:        *msg,
	}
	h.NetBroadcast(h.ID, ppMsg)
}

func (h *Handler) HandlePrePrepare(msg *PrePrepareMsg) {
	// Check if request sig is valid
	req := &msg.Req
	clientPubkey := h.GetClientPubkey(req.Client)
	reqSig := req.Sig
	req.Sig = nil
	reqDigest := h.Hash(req)
	err := h.PubkeyVerify(reqSig, reqDigest, clientPubkey)
	if err != nil {
		log.Printf("error: request sig invalid when handling pre-prepare: client = %s, err = %s\n", req.Client, err)
		return
	}
	req.Sig = reqSig

	// Check if sig is valid
	pubkey := h.ReplicaPubkeys[h.getPrimary()]
	sig := msg.Sig
	msg.Sig = nil
	digest := h.Hash(msg)
	err = h.PubkeyVerify(sig, digest, pubkey)
	if err != nil {
		log.Printf("error: pre-prepare sig invalid: seq = %d, err = %s\n", msg.Seq, err)
		return
	}
	msg.Sig = sig

	// Check if req digest matches
	if !bytes.Equal(msg.Digest, reqDigest) {
		log.Printf("error: pre-prepare reqDigest invalid: seq = %d\n", msg.Seq)
		return
	}

	// Check if view does not change
	if msg.View != h.View {
		log.Printf("error: pre-prepare view invalid: seq = %d\n", msg.Seq)
		return
	}

	// Check if req digest matches
	key := fmt.Sprintf("%d:%d", msg.View, msg.Seq)
	h.PrePrepareAcceptMapLock.Lock()
	oldDigest, ok := h.PrePrepareAcceptMap[key]
	if ok {
		if !bytes.Equal(oldDigest, msg.Digest) {
			log.Printf("error: pre-prepare msg accept conflict: seq = %d\n", msg.Seq)
		}
		return
	}
	h.PrePrepareAcceptMap[key] = msg.Digest
	h.PrePrepareAcceptMapLock.Unlock()

	// Save request
	rKey := hex.EncodeToString(msg.Digest)
	newReq := *req
	newReq.Sig = nil
	h.RequestAcceptMapLock.Lock()
	h.RequestAcceptMap[rKey] = &newReq
	h.RequestAcceptMapLock.Unlock()

	// TODO: Check seq between h and H

	// Gen and send prepare
	p := &Prepare{
		View:    msg.View,
		Seq:     msg.Seq,
		Digest:  msg.Digest,
		Replica: h.ID,
	}
	pDigest := h.Hash(p)
	p.Sig = h.PubkeySign(pDigest, h.privkey)
	// Handle self prepare
	h.HandlePrepare(p)
	h.NetBroadcast(h.ID, p)
}

func (h *Handler) HandlePrepare(msg *Prepare) {
	// Check if sig is valid
	pubkey := h.ReplicaPubkeys[msg.Replica]
	sig := msg.Sig
	msg.Sig = nil
	digest := h.Hash(msg)
	err := h.PubkeyVerify(sig, digest, pubkey)
	if err != nil {
		log.Printf("error: prepare sig invalid: seq = %d, err = %s\n", msg.Seq, err)
		return
	}
	msg.Sig = sig

	// Check if view does not change
	if msg.View != h.View {
		log.Printf("error: prepare view invalid: seq = %d\n", msg.Seq)
		return
	}

	// TODO: Check seq between h and H

	// Check if prepare is enough
	pKey := fmt.Sprintf("%d:%d:%s", msg.View, msg.Seq, hex.EncodeToString(msg.Digest))
	h.PrepareAcceptMapLock.Lock()
	replicas, ok := h.PrepareAcceptMap[pKey]
	if ok {
		// Exclude duplicate replica
		found := false
		for _, replica := range replicas {
			if replica == h.ID {
				found = true
				break
			}
		}
		if !found {
			replicas = append(replicas, h.ID)
		}
	} else {
		replicas = []int{h.ID}
	}
	h.PrepareAcceptMap[pKey] = replicas
	h.PrepareAcceptMapLock.Unlock()

	// If prepared
	if len(replicas) == 2*h.F+1 {
		// Gen and send commit
		c := &Commit{
			View:    msg.View,
			Seq:     msg.Seq,
			Digest:  msg.Digest,
			Replica: h.ID,
		}
		cDigest := h.Hash(c)
		c.Sig = h.PubkeySign(cDigest, h.privkey)
		h.HandleCommit(c)
		h.NetBroadcast(h.ID, c)
	}
}

func (h *Handler) HandleCommit(msg *Commit) {
	// Check if sig is valid
	pubkey := h.ReplicaPubkeys[msg.Replica]
	sig := msg.Sig
	msg.Sig = nil
	digest := h.Hash(msg)
	err := h.PubkeyVerify(sig, digest, pubkey)
	if err != nil {
		log.Printf("error: commit sig invalid: seq = %d, err = %s\n", msg.Seq, err)
		return
	}
	msg.Sig = sig

	// Check if view does not change
	if msg.View != h.View {
		log.Printf("error: commit view invalid: seq = %d\n", msg.Seq)
		return
	}

	// TODO: Check seq between h and H

	// Check if commit is enough
	key := fmt.Sprintf("%d:%d:%s", msg.View, msg.Seq, hex.EncodeToString(msg.Digest))
	h.CommitLocalAcceptMapLock.Lock()
	replicas, ok := h.CommitLocalAcceptMap[key]
	if ok {
		found := false
		for _, replica := range replicas {
			if replica == h.ID {
				found = true
				break
			}
		}
		if !found {
			replicas = append(replicas, h.ID)
		}
	} else {
		replicas = []int{h.ID}
	}
	h.CommitLocalAcceptMap[key] = replicas

	// Prepare prepared for checking
	pKey := fmt.Sprintf("%d:%d:%s", msg.View, msg.Seq, hex.EncodeToString(msg.Digest))
	h.PrepareAcceptMapLock.Lock()
	pReplicas := h.PrepareAcceptMap[pKey]
	h.PrepareAcceptMapLock.Unlock()

	// If committed-local
	if len(replicas) == 2*h.F+1 && len(pReplicas) >= 2*h.F+1 {
		// Fetch request for operation
		h.RequestAcceptMapLock.Lock()
		req, _ := h.RequestAcceptMap[hex.EncodeToString(msg.Digest)]
		h.RequestAcceptMapLock.Unlock()

		// Tansform state for state machine
		nextState, res := h.Transform(h.State, req.Op)
		h.State = nextState

		r := &Reply{
			View:      msg.View,
			Timestamp: req.Timestamp,
			Client:    req.Client,
			Replica:   h.ID,
			Result:    res,
		}

		// Cache last result
		h.LastResultMapLock.Lock()
		h.LastResultMap[hex.EncodeToString(msg.Digest)] = r
		h.LastResultMapLock.Unlock()

		h.NetReply(req.Client, r)
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
	NetSend      func(id int, msg any)
	NetReply     func(client string, msg any)
	NetBroadcast func(id int, msg any)
}

type GetPubkeyFuncSet struct {
	GetClientPubkey func(client string) []byte
	ReplicaPubkeys  [][]byte
}

type DigestFuncSet struct {
	// Should keep data not modified
	Hash func(data any) []byte
}

type PubkeyFuncSet struct {
	PubkeySign   func(digest []byte, privkey []byte) []byte
	PubkeyVerify func(sig []byte, digest []byte, pubkey []byte) error
}
