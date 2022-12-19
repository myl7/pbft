// Copyright (C) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

package pbft

// NodeCommunicator needs to handle stable transmission, e.g., retrying / timeouts
type NodeCommunicator interface {
	Unicast(msgB []byte, toNode string) error
	// Broadcast has a msgType arg to differ large msgs, e.g., request & reply.
	// Broadcast should not sends the msg to itself, as that has been done in this library.
	Broadcast(msgB []byte, fromNode string, msgType string) error
	Return(msgB []byte, toUser string) error
}

type NodeStorage interface {
	Put(key string, val []byte) error
	Get(key string) (val []byte, err error)
}
