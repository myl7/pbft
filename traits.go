// Copyright (C) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

package pbft

import (
	"encoding/json"
)

type NodeParams struct {
	ID string
	// N is total node num
	// TODO: Allow not 3f + 1
	N int
	// PKs should include the node's own pubkey
	PKs map[string][]byte
	SK  []byte
}

// NodeCommunicator needs to handle stable transmission, e.g., retrying / timeouts
type NodeCommunicator interface {
	Unicast(msgB []byte, toNode string) error
	// Broadcast has a msgType arg to differ large msgs, e.g., request & reply.
	// Broadcast should not sends the msg to itself, as that has been done in this library.
	Broadcast(msgB []byte, fromNode string, msgType msgType) error
	Return(msgB []byte, toUser string) error
}

type msgType int

const (
	// msgTypeRequest Request is broadcasted with preprepare in HandleRequest
	msgTypeRequest msgType = iota
	msgTypePrePrepare
	msgTypePrepare
	msgTypeCommit
)

// NodeStorage key of it use / to separate namespaces
type NodeStorage interface {
	Put(key string, val []byte) error
	// Get returns nil if not found
	Get(key string) (val []byte, err error)
}

// nodeStorageSerde is used for (de)serializing objects for NodeStorage.
// TODO: Currently it is not public. Maybe in the future we will extend NodeStorage to allow users to custom this.
//
//lint:ignore U1000 Reversed for public in the future if possible
type nodeStorageSerde interface {
	// Ser should not panic with rational input (e.g., JSON), otherwise may panic
	Ser(obj any) []byte
	// De should not panic with Ser output, otherwise may panic
	De(b []byte, obj any)
}

var nodeStorageJSONSerde = nodeStorageJSONSerdeImpl{}

type nodeStorageJSONSerdeImpl struct{}

func (nodeStorageJSONSerdeImpl) Ser(obj any) []byte {
	b, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	return b
}

func (nodeStorageJSONSerdeImpl) De(b []byte, obj any) {
	err := json.Unmarshal(b, obj)
	if err != nil {
		panic(err)
	}
}

type NodeStateMachine interface {
	// Transform does computation, so it may be slow
	Transform(op []byte) (result []byte)
}

type NodeUserPKGetter interface {
	Get(user string) (pk []byte, err error)
}

type NodePrimaryGetter interface {
	Get(view int) (primary string, err error)
}
