package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"os"
	"sync"

	"github.com/myl7/pbft"
)

func main() {
	pkn := flag.Int("pkn", 50, "the number of key pairs to pre-generate")
	flag.Parse()
	if *pkn < 1 {
		panic("invalid pkn")
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() { defer wg.Done(); taskGenKeyPair(*pkn) }()
	wg.Wait()
}

func taskGenKeyPair(pkn int) {
	kps := make([]map[string][]byte, pkn)
	for i := 0; i < pkn; i++ {
		pk, sk, err := genKeyPair()
		if err != nil {
			panic(err)
		}

		kps[i] = map[string][]byte{
			"pk": pk,
			"sk": sk,
		}
	}

	kpsB, err := json.Marshal(kps)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile("test/data/key_pairs.json", kpsB, 0644)
	if err != nil {
		panic(err)
	}
}

func genKeyPair() ([]byte, []byte, error) {
	pkObj, skObj, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pk := pbft.SerPK(pkObj)
	sk := pbft.SerSK(skObj)
	return pk, sk, nil
}
