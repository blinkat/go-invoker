package core

import (
	cp "crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	//"fmt"
)

type KeyAlgorithm string
type KeySize string

const (
	ECC        = KeyAlgorithm("ECC")
	ECC_A128KW = KeyAlgorithm("ECC-A128KW")
	ECC_A192KW = KeyAlgorithm("ECC-A192KW")
	ECC_A256KW = KeyAlgorithm("ECC-A256KW")
)

const (
	ECC_SIZE_P224 = KeySize("P224")
	ECC_SIZE_P256 = KeySize("P256")
	ECC_SIZE_P384 = KeySize("P384")
	ECC_SIZE_P521 = KeySize("P521")
)

type key_base struct {
	key_size   int
	alg        EncryptionAlgorithm
	comp       CompressionAlgorithm
	recipients []key_inside
	key_alg    KeyAlgorithm
	cipher     cipher
}

func (k *key_base) algorithm() EncryptionAlgorithm {
	return k.alg
}

func (k *key_base) key_algorithm() KeyAlgorithm {
	return k.key_alg
}

func (k *key_base) compress_alg() CompressionAlgorithm {
	return k.comp
}

func (k *key_base) get_cipher() cipher {
	return k.cipher
}

type key_inside interface {
	algorithm() EncryptionAlgorithm
	encrypt_key(ck []byte, alg KeyAlgorithm) (recipient_info, error)
	decrypt_key(headers *raw_header, rep *recipient_info) ([]byte, error)
	gen_key() ([]byte, *raw_header, error)
	compress_alg() CompressionAlgorithm
	cipher_block() cipher
	key_algorithm() KeyAlgorithm
}

// ---------[ helper ]----------
var default_iv = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

func key_warp(block cp.Block, cek []byte) ([]byte, error) {
	if len(cek)%8 != 0 {
		return nil, errors.New("key warp must 8 byte")
	}

	n := len(cek) / 8
	r := make([][]byte, n)

	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], cek[i*8:])
	}

	buf := make([]byte, 16)
	tb := make([]byte, 8)
	copy(buf, default_iv)

	for t := 0; t < 6*n; t++ {
		copy(buf[8:], r[t%n])
		block.Encrypt(buf, buf)

		binary.BigEndian.PutUint64(tb, uint64(t+1))

		for i := 0; i < 8; i++ {
			buf[i] = buf[i] ^ tb[i]
		}
		copy(r[t%n], buf[8:])
	}

	out := make([]byte, (n+1)*8)
	copy(out, buf[:8])
	for i := range r {
		copy(out[(i+1)*8:], r[i])
	}
	return out, nil
}

func key_unwarp(block cp.Block, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%8 != 0 {
		return nil, errors.New("key warp must 8 byte")
	}

	n := (len(ciphertext) / 8) - 1
	r := make([][]byte, n)

	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], ciphertext[(i+1)*8:])
	}

	buf := make([]byte, 16)
	tb := make([]byte, 8)
	copy(buf[:8], ciphertext[:8])

	for t := 6*n - 1; t >= 0; t-- {
		binary.BigEndian.PutUint64(tb, uint64(t+1))

		for i := 0; i < 8; i++ {
			buf[i] = buf[i] ^ tb[i]
		}
		//fmt.Println(buf, r, t%n)
		copy(buf[8:], r[t%n])
		block.Decrypt(buf, buf)
		copy(r[t%n], buf[8:])
	}

	if subtle.ConstantTimeCompare(buf[:8], default_iv) == 0 {
		return nil, errors.New("failed to unwarp key")
	}
	out := make([]byte, n*8)
	for i := range r {
		copy(out[i*8:], r[i])
	}
	return out, nil
}
