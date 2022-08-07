// Copyright (c) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

package pkg

func NewDigestFuncSetDefault() *DigestFuncSet {
	return &DigestFuncSet{
		Hash: SHA3WithGobHash,
	}
}

func NewPubkeyFuncSetDefault() *PubkeyFuncSet {
	return &PubkeyFuncSet{
		PubkeySign:   RSAWithSHA3512Sign,
		PubkeyVerify: RSAWithSHA3512Verify,
	}
}

func NewDBSerdeFuncSetDefault() *DBSerdeFuncSet {
	return &DBSerdeFuncSet{
		DBSer: GobEnc,
		DBDe:  GobDec,
	}
}
