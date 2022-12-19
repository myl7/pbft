// Copyright (C) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

package pbft

import "google.golang.org/protobuf/proto"

type msgWithSig interface {
	proto.Message
	GetSig() []byte
	setSig([]byte)
}

// hashMsgWithoutSig panics if msg can not be marshaled after setting sig to nil
func hashMsgWithoutSig(msg msgWithSig) []byte {
	sig := msg.GetSig()
	msg.setSig(nil)
	defer msg.setSig(sig)

	msgb, err := proto.Marshal(msg)
	if err != nil {
		panic(err)
	}
	return hash(msgb)
}

// Add setters of sig for msgs
func (x *Request) setSig(sig []byte) {
	x.Sig = sig
}

func (x *PrePrepare) setSig(sig []byte) {
	x.Sig = sig
}

func (x *Prepare) setSig(sig []byte) {
	x.Sig = sig
}

func (x *Commit) setSig(sig []byte) {
	x.Sig = sig
}

func (x *Reply) setSig(sig []byte) {
	x.Sig = sig
}
