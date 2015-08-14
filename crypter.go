package invoker

import (
	"fmt"
	"github.com/blinkat/go-invoker/core"
)

type Algorithm int
type KeySize int
type GCM int

const (
	// size max
	_MAX_ECDH_SIZE = 4
	_MAX_ECDH_ALGO = 4
)

// inside type
const (
	_NONE = -1
	_ECC  = iota
)
const (
	ALGORITHM_ECDH = iota
	ALGORITHM_ECDH_A128KW
	ALGORITHM_ECDH_A192KW
	ALGORITHM_ECDH_A256KW
)
const (
	ECDH_SIZE_P224 = iota
	ECDH_SIZE_P256
	ECDH_SIZE_P384
	ECDH_SIZE_P521
)
const (
	A128GCM = iota
	A192GCM
	A256GCM
)

type Crypter interface {
	core.Crypto
}

func NewCrypter(alg Algorithm, gcm GCM, size KeySize) (Crypter, error) {
	if t := algorithm_condition(alg, size); t != _NONE {
		switch t {
		case _ECC:
			return new_ecc(alg, gcm, size)
		}
	}
	return nil, fmt.Errorf("algorithm type and size type is not same-type.")
}

func new_ecc(alg Algorithm, gcm GCM, size KeySize) (Crypter, error) {
	kalog := get_algo(alg)
	g := get_enc(gcm)
	s := get_size(size)
	c := core.DEFAULT

	return core.NewCrypto(g, kalog, c, s)
}

func algorithm_condition(alg Algorithm, size KeySize) int {
	//fmt.Println(alg, size)
	if int(alg) < _MAX_ECDH_ALGO && int(size) < _MAX_ECDH_SIZE {
		return _ECC
	}

	return _NONE
}

// params
func get_algo(alg Algorithm) core.KeyAlgorithm {
	switch alg {
	case ALGORITHM_ECDH:
		return core.ECC
	case ALGORITHM_ECDH_A128KW:
		return core.ECC_A128KW
	case ALGORITHM_ECDH_A192KW:
		return core.ECC_A192KW
	case ALGORITHM_ECDH_A256KW:
		return core.ECC_A256KW
	}
	return core.KeyAlgorithm("")
}
func get_enc(enc GCM) core.EncryptionAlgorithm {
	switch enc {
	case A128GCM:
		return core.A128GCM
	case A192GCM:
		return core.A192GCM
	case A256GCM:
		return core.A256GCM
	}
	return core.EncryptionAlgorithm("")
}

func get_size(s KeySize) core.KeySize {
	switch s {
	case ECDH_SIZE_P224:
		return core.ECC_SIZE_P224
	case ECDH_SIZE_P256:
		return core.ECC_SIZE_P256
	case ECDH_SIZE_P384:
		return core.ECC_SIZE_P384
	case ECDH_SIZE_P521:
		return core.ECC_SIZE_P521
	}

	return core.KeySize("")
}
