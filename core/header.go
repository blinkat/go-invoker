package core

type Header struct {
	KeyID     string
	Key       *WebKey
	Algorithm string
}

type raw_header struct {
	Alg  string               `json:"alg,omitempty"`
	Enc  EncryptionAlgorithm  `json:"enc,omitempty"`
	Zip  CompressionAlgorithm `json:"zip,omitempty`
	Crit []string             `json:"crit,omitempty"`
	Apu  encoder              `json:"apu,omitempty"`
	Apv  encoder              `json:"apv,omitempty"`
	Epk  *WebKey              `json:"epk,omitempty"`
	Iv   encoder              `json:"iv,omitempty"`
	Tag  encoder              `json:"tag,omitempty"`
	Key  *WebKey              `json:"key,omitempty"`
	ID   string               `json:"id,omitempty"`
}

func (r *raw_header) sanitized() *Header {
	return &Header{
		KeyID:     r.ID,
		Key:       r.Key,
		Algorithm: r.Alg,
	}
}

func (dst *raw_header) merge(src *raw_header) {
	if src == nil {
		return
	}

	if dst.Alg == "" {
		dst.Alg = src.Alg
	}
	if dst.Enc == "" {
		dst.Enc = src.Enc
	}
	if dst.Zip == "" {
		dst.Zip = src.Zip
	}
	if dst.Crit == nil {
		dst.Crit = src.Crit
	}
	if dst.Crit == nil {
		dst.Crit = src.Crit
	}
	if dst.Apu == nil {
		dst.Apu = src.Apu
	}
	if dst.Apv == nil {
		dst.Apv = src.Apv
	}
	if dst.Epk == nil {
		dst.Epk = src.Epk
	}
	if dst.Iv == nil {
		dst.Iv = src.Iv
	}
	if dst.Tag == nil {
		dst.Tag = src.Tag
	}
	if dst.ID == "" {
		dst.ID = src.ID
	}
	if dst.Key == nil {
		dst.Key = src.Key
	}
}

// type
type EncryptionAlgorithm string
type CompressionAlgorithm string

const (
	A128GCM = EncryptionAlgorithm("A128GCM")
	A192GCM = EncryptionAlgorithm("A192GCM")
	A256GCM = EncryptionAlgorithm("A256GCM")
)

const (
	NONE    = CompressionAlgorithm("")
	DEFAULT = CompressionAlgorithm("DEF")
)
