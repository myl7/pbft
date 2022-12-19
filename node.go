// Copyright (C) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

//go:generate protoc --go_out=. --go_opt=paths=source_relative msg.proto

package pbft

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"

	"google.golang.org/protobuf/proto"
)

type NodeAPI interface {
	HandleRequest(msgB []byte) error
	// HandlePrePrepare parses msgPpB as preprepare & msgReqB as request
	HandlePrePrepare(msgPpB []byte, msgReqB []byte) error
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

func (nd *Node) HandlePrePrepare(msgPpB []byte, msgReqB []byte) error {
	pp := &PrePrepare{}
	err := proto.Unmarshal(msgPpB, pp)
	if err != nil {
		return err
	}

	req := &Request{}
	err = proto.Unmarshal(msgReqB, req)
	if err != nil {
		return err
	}

	panic("not implemented") // TODO: Implement
}

func (nd *Node) HandlePrepare(msgB []byte) error {
	p := &Prepare{}
	err := proto.Unmarshal(msgB, p)
	if err != nil {
		return err
	}

	panic("not implemented") // TODO: Implement
}

func (nd *Node) HandleCommit(msgB []byte) error {
	c := &Commit{}
	err := proto.Unmarshal(msgB, c)
	if err != nil {
		return err
	}

	panic("not implemented") // TODO: Implement
}
