// Copyright (C) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

package pbft

import (
	"crypto/ed25519"

	"golang.org/x/crypto/sha3"
)

// Hash uses SHAKE256 with 64B output
func hash(data []byte) []byte {
	h := make([]byte, 64)
	sha3.ShakeSum256(h, data)
	return h
}

// verifySig uses Ed25519.
// Panic if pk is invalid. For others, same for sk.
func verifySig(digest []byte, sig []byte, pk []byte) bool {
	pkObj := dePK(pk)
	return ed25519.Verify(pkObj, digest, sig)
}

// genSig See [verifySig].
func genSig(digest []byte, sk []byte) []byte {
	skObj := deSK(sk)
	return ed25519.Sign(skObj, digest)
}

// dePK just does casting, since PublicKey is internally []byte in Golang, and we reuse it as (de)serialization
func dePK(pk []byte) ed25519.PublicKey {
	return pk
}

// SerPK See [dePK]
func SerPK(pk ed25519.PublicKey) []byte {
	return pk
}

// deSK See [dePK]
func deSK(sk []byte) ed25519.PrivateKey {
	return sk
}

// SerSK See [dePK]
func SerSK(sk ed25519.PrivateKey) []byte {
	return sk
}
