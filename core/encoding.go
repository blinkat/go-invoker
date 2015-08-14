package core

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
	"regexp"
	"strings"
)

func base64_url_encode(data []byte) string {
	ret := base64.URLEncoding.EncodeToString(data)
	return strings.TrimRight(ret, "=")
}

func base64_url_decode(data string) ([]byte, error) {
	ms := (4 - len(data)%4) % 4
	data += strings.Repeat("=", ms)
	return base64.URLEncoding.DecodeString(data)
}

func compress(alg CompressionAlgorithm, inp []byte) ([]byte, error) {
	switch alg {
	case DEFAULT:
		return deflate(inp)
	default:
		return inp, nil
	}
}

func decompress(alg CompressionAlgorithm, inp []byte) ([]byte, error) {
	switch alg {
	case DEFAULT:
		return inflate(inp)
	default:
		return inp, nil
	}
}

func deflate(inp []byte) ([]byte, error) {
	out := new(bytes.Buffer)
	writer, _ := flate.NewWriter(out, 1)
	io.Copy(writer, bytes.NewBuffer(inp))
	err := writer.Close()
	return out.Bytes(), err
}

func inflate(inp []byte) ([]byte, error) {
	out := new(bytes.Buffer)
	reader := flate.NewReader(bytes.NewBuffer(inp))

	_, err := io.Copy(out, reader)
	if err != nil {
		return nil, err
	}
	err = reader.Close()
	return out.Bytes(), err
}

var strip_white_space_regexp = regexp.MustCompile("\\s")

func strip_white(data string) string {
	return strip_white_space_regexp.ReplaceAllString(data, "")
}

func serialize_json(value interface{}) []byte {
	out, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}

	if string(out) == "null" {
		panic("can not serialize a nil pointer.")
	}
	return out
}

// encoder
type encoder []byte

func (e encoder) new_encoder_from_int(num uint64) encoder {
	var data encoder
	binary.BigEndian.PutUint64(data, num)
	data = encoder(bytes.TrimLeft([]byte(data), "\x00"))
	return data
}

func (e encoder) base64() string {
	return base64_url_encode([]byte(e))
}

func (e encoder) bytes() []byte {
	if e == nil {
		return nil
	}
	return []byte(e)
}

func (e encoder) bigint() *big.Int {
	return new(big.Int).SetBytes([]byte(e))
}

func (e encoder) to_int() int {
	return int(e.bigint().Int64())
}

func (e encoder) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.base64())
}

func (e *encoder) UnmarshalJSON(data []byte) error {
	var ret string
	err := json.Unmarshal(data, &ret)
	if err != nil {
		return err
	}

	if ret == "" {
		return nil
	}

	ded, err := base64_url_decode(ret)
	if err != nil {
		return err
	}

	*e = encoder(ded)
	return nil
}
