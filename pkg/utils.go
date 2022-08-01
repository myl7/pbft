// Copyright (c) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

package pkg

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
)

func GobEnc(data any) []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(data)
	if err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func GenSHA256Hash(ser func(data any) (bin []byte)) func(any) []byte {
	if ser == nil {
		ser = GobEnc
	}

	return func(data any) []byte {
		h := sha256.New()
		bin := ser(data)
		h.Write(bin)
		return h.Sum(nil)
	}
}

func RSAAndSHA256PubkeySign(digest []byte, privkey []byte) []byte {
	block, _ := pem.Decode(privkey)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		panic(err)
	}

	return sig
}

func RSAAndSHA256PubkeyVerify(sig []byte, digest []byte, pubkey []byte) error {
	block, _ := pem.Decode(pubkey)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	return rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA256, digest, sig)
}
