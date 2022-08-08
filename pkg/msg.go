// Copyright (c) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

// All msg types should be safe to copy by value.
// This may affect the type choices of Op and Result.
// When working on arrays in these msg types, the package would ensure immutability.
package pkg

// <>_{\sigma}
type WithSig[T Request | PrePrepare | Prepare | Commit | Reply | Checkpoint] struct {
	// <>
	Body T
	// \sigma, signature
	Sig []byte
}

// <REQUEST,o,t,c>
type Request struct {
	// o, operation
	Op any
	// t
	Timestamp int64
	// c
	Client string
}

// <PRE-PREPARE,v,n,d>
type PrePrepare struct {
	// v
	View int
	// n, sequence number
	Seq int
	// d, request digest
	Digest []byte
}

// <<PRE-PREPARE,v,n,d>_{\sigma_p},m>
type PrePrepareMsg struct {
	PP WithSig[PrePrepare]
	// m, request
	Req WithSig[Request]
}

// <PREPARE,v,n,d,i>
type Prepare struct {
	// v
	View int
	// n, sequence number
	Seq int
	// d, request digest
	Digest []byte
	// i
	Replica int
}

// <COMMIT,v,n,D(m),i>
type Commit struct {
	// v
	View int
	// n, sequence number
	Seq int
	// i
	Replica int
	// D(m), digest of request m
	Digest []byte
}

// <REPLY,v,t,c,i,r>
type Reply struct {
	// v
	View int
	// t
	Timestamp int64
	// c
	Client string
	// i
	Replica int
	// r
	Result any
}

// <CHECKPOINT,n,d,i>
type Checkpoint struct {
	// n
	Seq int
	// d
	StateDigest []byte
	// i
	Replica int
}
