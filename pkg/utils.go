package pkg

import (
	"bytes"
	"database/sql"
	_ "embed"
	"encoding/gob"
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
