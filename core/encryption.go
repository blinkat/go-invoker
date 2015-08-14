package core

import (
	"encoding/json"
	"fmt"
	"strings"
)

type raw_encryption struct {
	Protected    encoder            `json:"protected,omitempty"`
	Unprotected  *raw_header        `json:"unprotected,omitempty"`
	Header       *raw_header        `json:"header,omitempty"`
	Recipients   raw_recipient_info `json:"recipients,omitempty"`
	Aad          encoder            `json:"aad,omitempty"`
	EncryptedKey encoder            `json:"encrypted_key,omitempty"`
	Iv           encoder            `json:"iv,omitempty"`
	Ciphertext   encoder            `json:"ciphertext,omitempty"`
	Tag          encoder            `json:"tag,omitempty"`
}

type Encryption struct {
	Header                   *Header
	protected, unprotected   *raw_header
	recipients               recipient_info
	aad, iv, ciphertext, tag []byte
	original                 *raw_encryption
}

type recipient_info struct {
	header *raw_header
	key    []byte
}

type raw_recipient_info struct {
	Header *raw_header `json:"header,omitempty"`
	Key    string      `json:"key,omitempty"`
}

func (e *Encryption) GetAuthData() []byte {
	if e.aad != nil {
		out := make([]byte, len(e.aad))
		copy(out, e.aad)
		return out
	}
	return nil
}

func (e *Encryption) merged_header(recipient *recipient_info) *raw_header {
	out := raw_header{}
	out.merge(e.protected)
	out.merge(e.unprotected)

	if recipient != nil {
		out.merge(recipient.header)
	}
	return &out
}

func (e *Encryption) compute_auth_data() []byte {
	var protected string

	if e.original != nil {
		protected = e.original.Protected.base64()
	} else {
		protected = base64_url_encode(serialize_json(e.protected))
	}

	out := []byte(protected)
	if e.aad != nil {
		out = append(out, '.')
		out = append(out, []byte(base64_url_encode(e.aad))...)
	}
	return out
}

func ParseEncrypted(inp string) (*Encryption, error) {
	inp = strip_white(inp)
	if strings.HasPrefix(inp, "{") {
		return parse_encrypted_full([]byte(inp))
	}
	return parse_encrypted_compact(inp)
}

func parse_encrypted_full(inp []byte) (*Encryption, error) {
	var ret raw_encryption
	err := json.Unmarshal(inp, &ret)
	if err != nil {
		return nil, err
	}
	return ret.sanitized()
}

func parse_encrypted_compact(inp string) (*Encryption, error) {
	parts := strings.Split(inp, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("compact format error")
	}

	r_pro, err := base64_url_decode(parts[0])
	if err != nil {
		return nil, err
	}

	e_key, err := base64_url_decode(parts[1])
	if err != nil {
		return nil, err
	}

	iv, err := base64_url_decode(parts[2])
	if err != nil {
		return nil, err
	}

	cip, err := base64_url_decode(parts[3])
	if err != nil {
		return nil, err
	}

	tag, err := base64_url_decode(parts[4])
	if err != nil {
		return nil, err
	}

	raw := &raw_encryption{
		Protected:    encoder(r_pro),
		EncryptedKey: encoder(e_key),
		Iv:           encoder(iv),
		Ciphertext:   encoder(cip),
		Tag:          encoder(tag),
	}
	return raw.sanitized()
}

// raw encryption
func (r *raw_encryption) sanitized() (*Encryption, error) {
	ret := &Encryption{
		original:    r,
		unprotected: r.Unprotected,
	}
	ret.Header = ret.merged_header(nil).sanitized()

	if r.Protected != nil && len(r.Protected.bytes()) > 0 {
		err := json.Unmarshal(r.Protected.bytes(), &ret.protected)
		if err != nil {
			//ret, err = nil, fmt.Errorf("invalid protected header")
			//fmt.Println("err:", err)
			return nil, fmt.Errorf("invalid protected header")
		}
	}
	if r.Recipients.Header == nil || r.Recipients.Key == "" {
		ret.recipients = recipient_info{
			header: r.Header,
			key:    r.EncryptedKey.bytes(),
		}
	} else {
		key, err := base64_url_decode(r.Recipients.Key)
		if err != nil {
			return nil, err
		}
		ret.recipients = recipient_info{
			header: r.Recipients.Header,
			key:    key,
		}
	}

	// if len(r.Recipients) == 0 {
	// 	ret.recipients = recipient_info{
	// 		header: r.Header,
	// 		key:    r.EncryptedKey.bytes(),
	// 	}
	// } else {
	// 	//ret.recipients = make([]recipient_info, len(r.Recipients))
	// 	// for re := range r.Recipients {
	// 	// 	key, err := base64_url_decode(r.Recipients[re].Key)
	// 	// 	if err != nil {
	// 	// 		//ret, err = nil, fmt.Errorf("sanitized error")
	// 	// 		return nil, fmt.Errorf("sanitized error")
	// 	// 	}

	// 	// 	ret.recipients[re].header = r.Recipients[re].Header
	// 	// 	ret.recipients[re].key = key
	// 	// }
	// 	key, err := base64_url_decode(r.Recipients.Key)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	ret.recipients = recipient_info{
	// 		header: r.Recipients.Header,
	// 		key:    key,
	// 	}
	// }

	// for _, rec := range ret.recipients {
	// 	headers := ret.merged_header(&rec)
	// 	if headers.Alg == "" || headers.Enc == "" {
	// 		//ret, err = nil, fmt.Errorf("message is missing")
	// 		return nil, fmt.Errorf("message is missing")
	// 	}
	// }

	if hs := ret.merged_header(&ret.recipients); hs.Alg == "" || hs.Enc == "" {
		return nil, fmt.Errorf("miss alg/enc header")
	}

	ret.iv = r.Iv.bytes()
	ret.ciphertext = r.Ciphertext.bytes()
	ret.tag = r.Tag.bytes()
	ret.aad = r.Aad.bytes()
	return ret, nil
}

func (e *Encryption) CompactSerialize() (string, error) {
	// if e.recipients.header > 1 || e.unprotected != nil || e.recipients[0].header != nil {
	// 	return "", fmt.Errorf("compact serialize error")
	// }

	p := serialize_json(e.protected)

	return fmt.Sprintf("%s.%s.%s.%s.%s",
		base64_url_encode(p),
		base64_url_encode(e.recipients.key),
		base64_url_encode(e.iv),
		base64_url_encode(e.ciphertext),
		base64_url_encode(e.tag),
	), nil
}

func (e *Encryption) FullSerialize() []byte {
	raw := raw_encryption{
		Unprotected:  e.unprotected,
		Recipients:   raw_recipient_info{},
		Aad:          encoder(e.aad),
		EncryptedKey: encoder(e.recipients.key),
		Iv:           encoder(e.iv),
		Ciphertext:   encoder(e.ciphertext),
		Tag:          encoder(e.tag),
	}

	// if len(e.recipients) > 1 {
	// 	for _, rec := range e.recipients {
	// 		info := raw_recipient_info{
	// 			Header: rec.header,
	// 			Key:    base64_url_encode(rec.key),
	// 		}
	// 		raw.Recipients = append(raw.Recipients, info)
	// 	}
	// } else {
	// 	raw.Header = e.recipients[0].header
	// 	raw.EncryptedKey = encoder(e.recipients[0].key)
	// }
	raw.Header = e.recipients.header
	raw.EncryptedKey = encoder(e.recipients.key)

	raw.Protected = encoder(serialize_json(e.protected))
	return serialize_json(raw)
}
