// Copyright (c) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

package pkg

func NewDigestFuncSetDefault() *DigestFuncSet {
	return &DigestFuncSet{
		Hash: SHA512WithGobHash,
	}
}

func NewPubkeyFuncSetDefault() *PubkeyFuncSet {
	return &PubkeyFuncSet{
		PubkeySign:   RSAWithSHA512Sign,
		PubkeyVerify: RSAWithSHA512Verify,
	}
}

func NewDBSerdeFuncSetDefault() *DBSerdeFuncSet {
	return &DBSerdeFuncSet{
		DBSer: GobEnc,
		DBDe:  GobDec,
	}
}
