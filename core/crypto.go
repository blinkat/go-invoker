package core

import (
	"fmt"
	"strings"
)

type Crypto interface {
	Encrypt(src []byte) ([]byte, error)
	Decrypt(cip []byte) ([]byte, error)
}

type crypter struct {
	key key_inside
}

func (c *crypter) Encrypt(plaintext []byte) ([]byte, error) {
	var err error
	ret := &Encryption{}
	ret.protected = &raw_header{
		Enc: c.key.algorithm(),
	}

	cek, header, err := c.key.gen_key()
	if err != nil {
		return nil, err
	}

	ret.protected.merge(header)

	if rec, err := c.key.encrypt_key(cek, c.key.key_algorithm()); err != nil {
		return nil, err
	} else {
		rec.header.Alg = string(c.key.key_algorithm())
		ret.recipients = rec
	}

	ret.protected.merge(ret.recipients.header)
	ret.recipients.header = nil

	if c.key.compress_alg() != NONE {
		plaintext, err = compress(c.key.compress_alg(), plaintext)
		if err != nil {
			return nil, err
		}
		ret.protected.Zip = c.key.compress_alg()
	}

	auth := ret.compute_auth_data()
	parts, err := c.key.cipher_block().encrypt(cek, auth, plaintext)
	if err != nil {
		return nil, err
	}

	ret.iv = parts.iv
	ret.ciphertext = parts.ciphertext
	ret.tag = parts.tag

	// ----------- test ------------
	tmp, err := c.DecryptEnc(ret)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(tmp)

	return ret.FullSerialize(), nil
}

func (c *crypter) Decrypt(ciphertext []byte) ([]byte, error) {
	enc, err := ParseEncrypted(string(ciphertext))
	//fmt.Println(string(enc.Header.Key.MarshalJSON()))
	if err != nil {
		return nil, err
	}
	return c.DecryptEnc(enc)
}

func (c *crypter) DecryptEnc(enc *Encryption) ([]byte, error) {
	headers := enc.merged_header(nil)

	cip := get_cipher(headers.Enc)
	if cip == nil {
		return nil, fmt.Errorf("invalid enc '%s'", string(headers.Enc))
	}

	parts := &aead_parts{
		iv:         enc.iv,
		ciphertext: enc.ciphertext,
		tag:        enc.tag,
	}

	auth := enc.compute_auth_data()

	var plaintext []byte
	rec_header := enc.merged_header(&enc.recipients)
	if cek, err := c.key.decrypt_key(rec_header, &enc.recipients); err != nil {
		return nil, err
	} else {
		plaintext, err = cip.decrypt(cek, auth, parts)
		if err != nil {
			return nil, err
		}
	}

	if plaintext == nil {
		return nil, fmt.Errorf("decrypt failed.")
	}

	var err error
	if enc.protected.Zip != "" {
		plaintext, err = decompress(enc.protected.Zip, plaintext)
	}
	return plaintext, err
}

// ctor
func NewCrypto(alog EncryptionAlgorithm, kalgo KeyAlgorithm, calog CompressionAlgorithm, size KeySize) (Crypto, error) {
	c := &crypter{}
	if strings.Index(string(kalgo), "ECC") >= 0 {
		k, err := new_ec_key(alog, kalgo, calog, size)
		if err != nil {
			return nil, err
		}
		c.key = k
	}
	return c, nil
}
