package test

import (
	"encoding/json"
	"os"
	"testing"
)

type kp struct {
	PK []byte `json:"pk"`
	SK []byte `json:"sk"`
}

func LoadTestKPs(t *testing.T) []kp {
	kpsB, err := os.ReadFile("test/data/key_pairs.json")
	if err != nil {
		t.Fatal(err)
	}

	var kps []kp
	err = json.Unmarshal(kpsB, &kps)
	if err != nil {
		t.Fatal(err)
	}

	return kps
}
