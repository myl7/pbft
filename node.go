// Copyright (C) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

//go:generate protoc --go_out=. --go_opt=paths=source_relative msg.proto

package pbft

import "google.golang.org/protobuf/proto"

type NodeAPI interface {
	HandleRequest(msgB []byte) error
	// HandlePrePrepare parses msgPpB as preprepare & msgReqB as request
	HandlePrePrepare(msgPpB []byte, msgReqB []byte) error
	HandlePrepare(msgB []byte) error
	HandleCommit(msgB []byte) error
}

type Node struct {
	nc NodeCommunicator
	ns NodeStorage
}

func NewNode(nc NodeCommunicator, ns NodeStorage) *Node {
	return &Node{
		nc: nc,
		ns: ns,
	}
}

func (nd *Node) HandleRequest(msgB []byte) error {
	req := &Request{}
	err := proto.Unmarshal(msgB, req)
	if err != nil {
		return err
	}

	panic("not implemented") // TODO: Implement
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
