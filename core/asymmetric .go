package core

import (
	"crypto"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/rand"
	_ "crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/blinkat/go-invoker/concat"
)

// type PublicKey interface {
// 	Encrypt([]byte) []byte
// }

// type PrivateKey interface {
// 	Decrypt([]byte) []byte
// }

// type PublicKey interface {
// 	decrypt_key(header *raw_header, rec *recipient_info) (error, []byte)
// 	encrypt_key(cek []byte, alg KeyAlgorithm) (recipient_info, error)
// }

type Asymmetric interface {
	Public() interface{}
	Private() interface{}
}

// type ec_curve_type string

// const (
// 	p224 = ec_curve_type("P224")
// 	p256 = ec_curve_type("P256")
// 	p384 = ec_curve_type("P384")
// 	p521 = ec_curve_type("P521")
// )

// --- ec ----
type ec_private struct {
	key_base
	ec_key              *ecdsa.PrivateKey
	pub                 *ec_public
	iv, ciphertext, tag []byte
}

type ec_public struct {
	key_base
	ec_key *ecdsa.PublicKey
}

func (e *ec_private) Public() interface{} {
	return e.pub.ec_key
}

func (e *ec_private) Private() interface{} {
	return e.ec_key
}

func (e *ec_private) cipher_block() cipher {
	return e.cipher
}

func (e *ec_private) gen_key() ([]byte, *raw_header, error) {
	return e.pub.gen_key()
}

// func (e *ec_private) decrypt_key(header *raw_header, rec *recipient_info) ([]byte, error) {
// 	return e.pub.decrypt_key(header, rec)
// }

func (e *ec_private) encrypt_key(cek []byte, alg KeyAlgorithm) (recipient_info, error) {
	return e.pub.encrypt_key(cek, alg)
}

func new_ec_key(alog EncryptionAlgorithm, kalgo KeyAlgorithm, calog CompressionAlgorithm, curve KeySize) (key_inside, error) {
	k := &ec_private{}
	k.alg = alog
	k.comp = calog
	k.key_alg = kalgo

	cur := get_curve(string(curve))
	if cur == nil {
		return nil, fmt.Errorf("failed curve. '%s", string(curve))
	}
	if ck, err := ecdsa.GenerateKey(cur, rand.Reader); err != nil {
		return nil, err
	} else {
		k.ec_key = ck
		k.pub = &ec_public{
			ec_key: &ck.PublicKey,
		}
		k.pub.alg = k.alg
		k.pub.comp = k.comp
		k.pub.key_alg = k.key_alg

		k.cipher = get_cipher(k.alg)
		k.key_size = k.cipher.size()
		k.pub.key_size = k.cipher.size()
	}

	return k, nil
}

// ---- pub -----
func (e *ec_public) gen_key() ([]byte, *raw_header, error) {
	prk, err := ecdsa.GenerateKey(e.ec_key.Curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	out := derive_ecc(string(e.key_alg), []byte{}, []byte{}, e.ec_key, prk, e.key_size)
	//fmt.Println(e.key_size)

	headers := &raw_header{
		Epk: &WebKey{
			Key: &prk.PublicKey,
		},
	}
	return out, headers, nil
}

func (e *ec_private) decrypt_key(header *raw_header, rec *recipient_info) ([]byte, error) {
	if header.Epk == nil {
		return nil, fmt.Errorf("miss epk")
	}

	puk_key, ok := header.Epk.Key.(*ecdsa.PublicKey)
	if puk_key == nil || !ok {
		return nil, fmt.Errorf("invalid epk")
	}

	apu := header.Apu.bytes()
	apv := header.Apv.bytes()

	//prk, err := ecdsa.GenerateKey(e.ec_key.Curve, rand.Reader)
	//if err != nil {
	//	return nil, err
	//}
	//fmt.Println(e.key_size)
	//fmt.Println(header.Alg, header.Enc)
	if KeyAlgorithm(header.Alg) == ECC {
		return derive_ecc(string(header.Enc), apu, apv, puk_key, e.ec_key, e.key_size), nil
	}
	key := derive_ecc(header.Alg, apu, apv, puk_key, e.ec_key, e.key_size)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return key_unwarp(block, rec.key)
}

func (e *ec_public) encrypt_key(cek []byte, alg KeyAlgorithm) (recipient_info, error) {
	switch alg {
	case ECC:
		return recipient_info{
			header: &raw_header{},
		}, nil
	case ECC_A128KW, ECC_A192KW, ECC_A256KW:
	default:
		return recipient_info{}, fmt.Errorf("failed encrypt key")
	}

	kek, header, err := e.gen_key()
	if err != nil {
		return recipient_info{}, err
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return recipient_info{}, err
	}

	jek, err := key_warp(block, cek)
	if err != nil {
		return recipient_info{}, err
	}

	return recipient_info{
		key:    jek,
		header: header,
	}, nil
}

// ----- helper ------
func derive_ecc(alg string, apu, apv []byte, puk *ecdsa.PublicKey, prk *ecdsa.PrivateKey, size int) []byte {
	algID := length_prefixed([]byte(alg))
	pt_u := length_prefixed(apu)
	pt_v := length_prefixed(apv)

	sup := make([]byte, 4)
	binary.BigEndian.PutUint32(sup, uint32(size)*8)

	z, _ := puk.Curve.ScalarMult(puk.X, puk.Y, prk.D.Bytes())
	reader := concat.NewConcatKey(crypto.SHA256, z.Bytes(), algID, pt_u, pt_v, sup, []byte{})
	key := make([]byte, size)
	reader.Read(key)
	return key
}

func length_prefixed(data []byte) []byte {
	out := make([]byte, len(data)+4)
	binary.BigEndian.PutUint32(out, uint32(len(data)))
	copy(out[4:], data)
	return out
}
