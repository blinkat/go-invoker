package core

type aead_parts struct {
	iv, ciphertext, tag []byte
}
