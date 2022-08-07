package pkg

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"database/sql"
	_ "embed"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
)

// Serde

func GobEnc(obj any) []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(obj)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func GobDec(bin []byte, ptr any) {
	buf := bytes.NewBuffer(bin)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(ptr)
	if err != nil {
		panic(err)
	}
}

// DB

//go:embed schema.sql
var Schema string

func InitDB(db *sql.DB) {
	_, err := db.Exec(Schema)
	if err != nil {
		panic(err)
	}
}

// String to/from integers

func splitStrToInt(s string, sep string) []int {
	if s == "" {
		return nil
	}

	ss := strings.Split(s, sep)
	ints := make([]int, len(ss))
	for i, s := range ss {
		var err error
		ints[i], err = strconv.Atoi(s)
		if err != nil {
			panic(err)
		}
	}
	return ints
}

func joinIntToStr(ints []int, sep string) string {
	ss := make([]string, len(ints))
	for i, n := range ints {
		ss[i] = strconv.Itoa(n)
	}
	return strings.Join(ss, sep)
}

// Pubkey

func RSAWithSHA3512Sign(digest []byte, privkey []byte) []byte {
	key := DeRSAPrivkey(privkey)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, digest)
	if err != nil {
		panic(err)
	}

	return sig
}

func RSAWithSHA3512Verify(sig []byte, digest []byte, pubkey []byte) error {
	key := DeRSAPubkey(pubkey)
	err := rsa.VerifyPKCS1v15(key, crypto.SHA512, digest, sig)
	if err != nil {
		return err
	}

	return nil
}

// Pubkey serde

func SerRSAPubkey(pubkey *rsa.PublicKey) []byte {
	b, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		panic(err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	}
	return pem.EncodeToMemory(block)
}

func SerRSAPrivkey(privkey *rsa.PrivateKey) []byte {
	b := x509.MarshalPKCS1PrivateKey(privkey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: b,
	}
	return pem.EncodeToMemory(block)
}

func DeRSAPubkey(pubkey []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pubkey)
	if block == nil {
		panic(errors.New("invalid public key"))
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	return key.(*rsa.PublicKey)
}

func DeRSAPrivkey(privkey []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(privkey)
	if block == nil {
		panic(errors.New("invalid private key"))
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	return key
}

// Hash

func SHA3WithGobHash(data any) []byte {
	b := GobEnc(data)
	digest := sha512.Sum512(b)
	return digest[:]
}
