// Copyright (C) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

//go:generate protoc --go_out=. --go_opt=paths=source_relative msg.proto

package pbft

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"

	"google.golang.org/protobuf/proto"
)

type NodeAPI interface {
	HandleRequest(msgB []byte) error
	// HandlePrePrepare parses msgPPB as preprepare & msgReqB as request
	HandlePrePrepare(msgPPB []byte, msgReqB []byte) error
	HandlePrepare(msgB []byte) error
	HandleCommit(msgB []byte) error
}

type Node struct {
	np   NodeParams
	nc   NodeCommunicator
	ns   NodeStorage
	nsm  NodeStateMachine
	nupg NodeUserPKGetter
	npg  NodePrimaryGetter
	// Lock all inner states of the node
	lock sync.Mutex
	seq  int64
	view int
}

func NewNode(np NodeParams, nc NodeCommunicator, ns NodeStorage, nsm NodeStateMachine, nupg NodeUserPKGetter, npg NodePrimaryGetter) *Node {
	return &Node{
		np:   np,
		nc:   nc,
		ns:   ns,
		nsm:  nsm,
		nupg: nupg,
		npg:  npg,
	}
}

func (nd *Node) HandleRequest(msgB []byte) error {
	nd.lock.Lock()
	defer nd.lock.Unlock()

	req := &Request{}
	err := proto.Unmarshal(msgB, req)
	if err != nil {
		return err
	}

	// Check if timestamp is newer than before
	latestTB, err := nd.ns.Get(fmt.Sprintf("latest-t/%s", req.GetUser()))
	if err != nil {
		return err
	}
	if latestTB != nil {
		latestT, err := strconv.ParseInt(string(latestTB), 10, 64)
		if err != nil {
			return ErrInvalidStorage
		}
		if req.GetTimestamp() <= latestT {
			return ErrTimestampNotNew
		}
	}
	err = nd.ns.Put(fmt.Sprintf("latest-t/%s", req.GetUser()), []byte(strconv.FormatInt(req.GetTimestamp(), 10)))
	if err != nil {
		return err
	}

	// Check if the reply is still cached
	latestRepB, err := nd.ns.Get(fmt.Sprintf("latest-rep/%s", req.GetUser()))
	if err != nil {
		return err
	}
	if latestRepB != nil {
		latestRep := &Reply{}
		err = proto.Unmarshal(latestRepB, latestRep)
		if err != nil {
			return err
		}
		if latestRep.GetTimestamp() == req.GetTimestamp() {
			return nd.nc.Return(latestRepB, req.GetUser())
		}
	}

	// Check if here is the primary, otherwise forward the request to the primary
	primary, err := nd.npg.Get(nd.view)
	if err != nil {
		return err
	}
	if primary != nd.np.ID {
		return nd.nc.Unicast(msgB, primary)
	}

	reqSigDigest := hashMsgWithoutSig(req)
	uPK, err := nd.nupg.Get(req.GetUser())
	if err != nil {
		return err
	}
	if !verifySig(reqSigDigest, req.GetSig(), uPK) {
		return ErrInvalidSig
	}

	reqDigest := hash(msgB)
	pp := &PrePrepare{
		View:   int32(nd.view),
		Seq:    nd.seq,
		Digest: reqDigest,
	}
	ppSigDigest := hashMsgWithoutSig(pp)
	pp.Sig = genSig(ppSigDigest, nd.np.SK)
	ppB, err := proto.Marshal(pp)
	if err != nil {
		return err
	}

	nd.seq++

	err = nd.ns.Put(fmt.Sprintf("request/%s", hex.EncodeToString(reqDigest)), msgB)
	if err != nil {
		return err
	}
	err = nd.ns.Put(fmt.Sprintf("preprepare/%d/%d", pp.View, pp.Seq), ppB)
	if err != nil {
		return err
	}

	err = nd.nc.Broadcast(ppB, nd.np.ID, msgTypePrePrepare)
	if err != nil {
		return err
	}

	// TODO: Defer broadcasting of request, since it is large
	err = nd.nc.Broadcast(msgB, nd.np.ID, msgTypeRequest)
	if err != nil {
		return err
	}

	return nil
}

func (nd *Node) HandlePrePrepare(msgPPB []byte, msgReqB []byte) error {
	nd.lock.Lock()
	defer nd.lock.Unlock()

	pp := &PrePrepare{}
	err := proto.Unmarshal(msgPPB, pp)
	if err != nil {
		return err
	}

	ppSigDigest := hashMsgWithoutSig(pp)
	ndPK, ok := nd.np.PKs[nd.np.ID]
	if !ok {
		return ErrUnknownNodeID
	}
	if !verifySig(ppSigDigest, pp.GetSig(), ndPK) {
		return ErrInvalidSig
	}

	req := &Request{}
	err = proto.Unmarshal(msgReqB, req)
	if err != nil {
		return err
	}

	reqSigDigest := hashMsgWithoutSig(req)
	uPK, err := nd.nupg.Get(req.GetUser())
	if err != nil {
		return err
	}
	if !verifySig(reqSigDigest, req.GetSig(), uPK) {
		return ErrInvalidSig
	}

	reqDigest := hash(msgReqB)
	if !bytes.Equal(reqDigest, pp.GetDigest()) {
		return ErrUnmatchedDigest
	}

	if pp.GetView() != int32(nd.view) {
		return ErrUnmatchedView
	}

	// Check duplicated preprepare
	prePPB, err := nd.ns.Get(fmt.Sprintf("preprepare/%d/%d", pp.GetView(), pp.GetSeq()))
	if err != nil {
		return err
	}
	if prePPB != nil {
		if !bytes.Equal(prePPB, msgPPB) {
			return ErrUnmatchedPP
		}
	} else {
		err = nd.ns.Put(fmt.Sprintf("preprepare/%d/%d", pp.GetView(), pp.GetSeq()), msgPPB)
		if err != nil {
			return err
		}
	}

	err = nd.ns.Put(fmt.Sprintf("request/%s", hex.EncodeToString(reqDigest)), msgReqB)
	if err != nil {
		return err
	}

	p := &Prepare{
		View:   pp.GetView(),
		Seq:    pp.GetSeq(),
		Digest: pp.GetDigest(),
		Node:   nd.np.ID,
	}
	pSigDigest := hashMsgWithoutSig(p)
	p.Sig = genSig(pSigDigest, nd.np.SK)
	pB, err := proto.Marshal(p)
	if err != nil {
		return err
	}

	err = nd.nc.Broadcast(pB, nd.np.ID, msgTypePrepare)
	if err != nil {
		return err
	}

	go nd.HandlePrepare(pB)

	return nil
}

func (nd *Node) HandlePrepare(msgB []byte) error {
	nd.lock.Lock()
	defer nd.lock.Unlock()

	p := &Prepare{}
	err := proto.Unmarshal(msgB, p)
	if err != nil {
		return err
	}

	pSigDigest := hashMsgWithoutSig(p)
	ndPK, ok := nd.np.PKs[p.GetNode()]
	if !ok {
		return ErrUnknownNodeID
	}
	if !verifySig(pSigDigest, p.GetSig(), ndPK) {
		return ErrInvalidSig
	}

	if p.GetView() != int32(nd.view) {
		return ErrUnmatchedView
	}

	// Check prepare num
	pNodes := make(map[string]bool)
	pNodesB, err := nd.ns.Get(fmt.Sprintf("p-nodes/%d/%d/%s", p.GetView(), p.GetSeq(), hex.EncodeToString(p.GetDigest())))
	if err != nil {
		return err
	}
	if pNodesB != nil {
		nodeStorageJSONSerde.De(pNodesB, &pNodes)
	}

	pNodes[p.GetNode()] = true

	if len(pNodes) != 2*int((nd.np.N-1)/3) {
		return nil
	}
	// If just prepared.
	// TODO: In the edge case, the node may first get enough commits and committed-local, then get enough enough prepares and prepared. So we do also need to check commit num here. But that is too unrealistic so currently we just ignore it.

	c := &Commit{
		View:   p.GetView(),
		Seq:    p.GetSeq(),
		Digest: p.GetDigest(),
		Node:   nd.np.ID,
	}
	cSigDigest := hashMsgWithoutSig(c)
	c.Sig = genSig(cSigDigest, nd.np.SK)
	cB, err := proto.Marshal(c)
	if err != nil {
		return err
	}

	err = nd.nc.Broadcast(cB, nd.np.ID, msgTypeCommit)
	if err != nil {
		return err
	}

	go nd.HandleCommit(cB)

	return nil
}

func (nd *Node) HandleCommit(msgB []byte) error {
	nd.lock.Lock()
	defer nd.lock.Unlock()

	c := &Commit{}
	err := proto.Unmarshal(msgB, c)
	if err != nil {
		return err
	}

	cSigDigest := hashMsgWithoutSig(c)
	ndPK, ok := nd.np.PKs[c.GetNode()]
	if !ok {
		return ErrUnknownNodeID
	}
	if !verifySig(cSigDigest, c.GetSig(), ndPK) {
		return ErrInvalidSig
	}

	if c.GetView() != int32(nd.view) {
		return ErrUnmatchedView
	}

	// Check commit num
	cNodes := make(map[string]bool)
	cNodesB, err := nd.ns.Get(fmt.Sprintf("c-nodes/%d/%d/%s", c.GetView(), c.GetSeq(), hex.EncodeToString(c.GetDigest())))
	if err != nil {
		return err
	}
	if cNodesB != nil {
		nodeStorageJSONSerde.De(cNodesB, &cNodes)
	}

	cNodes[c.GetNode()] = true

	if len(cNodes) != 2*int((nd.np.N-1)/3)+1 {
		return nil
	}
	// If just committed-local.
	// TODO: Committed-local also needs to check prepared. But that seems not to happen usually, so we currently ignore it.

	reqB, err := nd.ns.Get(fmt.Sprintf("request/%s", hex.EncodeToString(c.GetDigest())))
	if err != nil {
		return err
	}
	if reqB == nil {
		// This should not happen
		return ErrNoRequestAfterCommittedLocal
	}

	req := &Request{}
	err = proto.Unmarshal(reqB, req)
	if err != nil {
		return err
	}

	// The computation may be slow
	result := nd.nsm.Transform(req.GetOp())

	rep := &Reply{
		View:      c.GetView(),
		Timestamp: req.GetTimestamp(),
		User:      req.GetUser(),
		Node:      nd.np.ID,
		Result:    result,
	}
	repSigDigest := hashMsgWithoutSig(rep)
	rep.Sig = genSig(repSigDigest, nd.np.SK)
	repB, err := proto.Marshal(rep)
	if err != nil {
		return err
	}

	// Cache latest reply
	err = nd.ns.Put(fmt.Sprintf("latest-rep/%s", req.GetUser()), repB)
	if err != nil {
		return err
	}

	err = nd.nc.Return(repB, req.GetUser())
	if err != nil {
		return err
	}

	return nil
}
