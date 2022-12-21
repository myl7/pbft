// Copyright (C) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

// All traits do not need inner locking, because in the node they are accessed in handlers, and handlers all have a mutex lock so that only one handler is running at a time
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
	Unicast(msgB []byte, toNode string, msgType msgType) error
	// Broadcast should not sends the msg to itself, as that has been done in this library.
	Broadcast(msgB []byte, fromNode string, msgType msgType) error
	// BroadcastWithLarge is similar to [Broadcast], but it sends a small msg msgB together with a large msg msgLB, e.g., a preprepare with a request.
	// If you do not need the optimization, you can combine the two msgs and send them in one time.
	BroadcastWithLarge(msgB []byte, msgLB []byte, fromNode string, msgType msgType) error
	// Return can only send reply msg so no msgType is required
	Return(msgB []byte, toUser string) error
}

type msgType int

const (
	// msgTypeRequest Notice this is only used to identify the request sent to HandleRequest.
	// The request sent to HandlePrePrepare will still use msgTypePrePrepare.
	msgTypeRequest msgType = iota
	msgTypePrePrepare
	msgTypePrepare
	msgTypeCommit
	msgTypeReply
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
