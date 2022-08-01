// Copyright (c) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

package pkg

// <REQUEST,o,t,c>_{\sigma_c}
type Request struct {
	// o, operation
	Op any
	// t
	Timestamp int64
	// c
	Client string
	// \sigma_c, signature
	Sig []byte
}

// <PRE-PREPARE,v,n,d>_{\sigma_p}
type PrePrepare struct {
	// v
	View int
	// n, sequence number
	Seq int
	// d, request digest
	Digest []byte
	// \sigma_p
	Sig []byte
}

// <<PRE-PREPARE,v,n,d>_{\sigma_p},m>
type PrePrepareMsg struct {
	PrePrepare
	// m, request
	Req Request
}

// <PREPARE,v,n,d,i>_{\sigma_i}
type Prepare struct {
	// v
	View int
	// n, sequence number
	Seq int
	// d, request digest
	Digest []byte
	// i
	Replica int
	// \sigma_i
	Sig []byte
}

// <COMMIT,v,n,D(m),i>_{\sigma_i}
type Commit struct {
	// v
	View int
	// n, sequence number
	Seq int
	// i
	Replica int
	// D(m), digest of request m
	Digest []byte
	// \sigma_i
	Sig []byte
}

// <REPLY,v,t,c,i,r>_{\sigma_i}
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
	// \sigma_i
	Sig []byte
}
