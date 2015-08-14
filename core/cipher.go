package core

import (
	"crypto/aes"
	cp "crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

type cipher interface {
	encrypt(c, a, p []byte) (*aead_parts, error)
	decrypt(c, a []byte, p *aead_parts) ([]byte, error)
	size() int
}

type aes_cipher struct {
	key_bytes int
	auth_tag  int
	aead      func(key []byte) (cp.AEAD, error)
}

// ---------- aes cipher -----------
func (a *aes_cipher) size() int {
	return a.key_bytes
}

func (a *aes_cipher) encrypt(key, aad, pt []byte) (*aead_parts, error) {
	aead, err := a.aead(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aead.NonceSize())
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}

	cip := aead.Seal(nil, iv, pt, aad)
	offset := len(cip) - a.auth_tag
	fmt.Println("pk:", key)
	return &aead_parts{
		iv:         iv,
		ciphertext: cip[:offset],
		tag:        cip[offset:],
	}, nil
}

func (a *aes_cipher) decrypt(key, aad []byte, parts *aead_parts) ([]byte, error) {
	aead, err := a.aead(key)
	if err != nil {
		return nil, err
	}
	fmt.Println("dk:", key)
	return aead.Open(nil, parts.iv, append(parts.ciphertext, parts.tag...), aad)
}

func new_aes_gcm(size int) cipher {
	return &aes_cipher{
		key_bytes: size,
		auth_tag:  16,
		aead: func(key []byte) (cp.AEAD, error) {
			a, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cp.NewGCM(a)
		},
	}
}

func get_cipher(alg EncryptionAlgorithm) cipher {
	switch alg {
	case A128GCM:
		return new_aes_gcm(16)
	case A192GCM:
		return new_aes_gcm(24)
	case A256GCM:
		return new_aes_gcm(32)
	default:
		return nil
	}
}
