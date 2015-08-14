package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"reflect"
)

type raw_json_key struct {
	Type  string  `json:"type,omitempty"`
	ID    string  `json:"id,omitempty"`
	Curve string  `json:"curve,omitempty"`
	Alg   string  `json:"alg,omitempty"`
	X     encoder `json:"x,omitempty"`
	Y     encoder `json:"y,omitempty"`
	N     encoder `json:"n,omitempty"`
	E     encoder `json:"e,omitempty"`
	// -- Following fields are only used for private keys --
	// RSA uses D, P and Q, while ECDSA uses only D. Fields Dp, Dq, and Qi are
	// completely optional. Therefore for RSA/ECDSA, D != nil is a contract that
	// we have a private key whereas D == nil means we have only a public key.
	D  encoder `json:"d,omitempty"`
	P  encoder `json:"p,omitempty"`
	Q  encoder `json:"q,omitempty"`
	Dp encoder `json:"dp,omitempty"`
	Dq encoder `json:"dq,omitempty"`
	Qi encoder `json:"qi,omitempty"`
}

func (r *raw_json_key) to_ec_public() (*ecdsa.PublicKey, error) {
	curve := get_curve(r.Curve)
	if curve == nil {
		return nil, fmt.Errorf("unknow curve id: %s", r.Curve)
	}
	if r.X == nil || r.Y == nil {
		return nil, fmt.Errorf("invalid ec key")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     r.X.bigint(),
		Y:     r.Y.bigint(),
	}, nil
}

func (r *raw_json_key) to_ec_private() (*ecdsa.PrivateKey, error) {
	curve := get_curve(r.Curve)
	if curve == nil {
		return nil, fmt.Errorf("unknow curve id: %s", r.Curve)
	}

	if r.X == nil || r.Y == nil || r.D == nil {
		return nil, fmt.Errorf("invalid ec private key")
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     r.X.bigint(),
			Y:     r.Y.bigint(),
		},
		D: r.D.bigint(),
	}, nil
}

// ---------- [ key ] ----------
type WebKey struct {
	Key       interface{}
	KeyID     string
	Algorithm string
}

func (k *WebKey) MarshalJSON() ([]byte, error) {
	var raw *raw_json_key
	var err error

	switch key := k.Key.(type) {
	case *ecdsa.PublicKey:
		raw, err = from_ec_public(key)
	case *ecdsa.PrivateKey:
		raw, err = from_ec_private(key)

	default:
		return nil, fmt.Errorf("unknow key type '%s'", reflect.TypeOf(k.Key))
	}

	if err != nil {
		return nil, err
	}
	raw.ID = k.KeyID
	raw.Alg = k.Algorithm

	return json.Marshal(raw)
}

func (k *WebKey) UnmarshalJSON(data []byte) (err error) {
	var raw raw_json_key
	err = json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	var key interface{}
	switch raw.Type {
	case "ec":
		if raw.D != nil {
			key, err = raw.to_ec_private()
		} else {
			key, err = raw.to_ec_public()
		}

	default:
		err = fmt.Errorf("unknow json key")
	}

	if err == nil {
		k.Key = key
		k.KeyID = raw.ID
		k.Algorithm = raw.Alg
	}
	return
}

// --------- [ helper ] -------------
func from_ec_private(pk *ecdsa.PrivateKey) (*raw_json_key, error) {
	raw, err := from_ec_public(&pk.PublicKey)
	if err != nil {
		return nil, err
	}
	if pk.D == nil {
		return nil, fmt.Errorf("invalid ec private key")
	}
	raw.D = encoder(pk.D.Bytes())
	return raw, nil
}

func from_ec_public(pk *ecdsa.PublicKey) (*raw_json_key, error) {
	if pk == nil || pk.X == nil || pk.Y == nil {
		return nil, fmt.Errorf("invalid ec public key.")
	}

	key := &raw_json_key{
		Type: "ec",
		X:    encoder(pk.X.Bytes()),
		Y:    encoder(pk.Y.Bytes()),
	}

	key.Curve = curve_id(pk.Curve)
	if key.Curve == "" {
		return nil, fmt.Errorf("unknow curve")
	}
	return key, nil
}

func get_curve(id string) elliptic.Curve {
	switch id {
	case "P224":
		return elliptic.P224()
	case "P256":
		return elliptic.P256()
	case "P384":
		return elliptic.P384()
	case "P521":
		return elliptic.P521()
	default:
		return nil
	}
}

func curve_id(c elliptic.Curve) string {
	switch c {
	case elliptic.P224():
		return "P224"
	case elliptic.P256():
		return "P256"
	case elliptic.P384():
		return "P384"
	case elliptic.P521():
		return "P521"
	default:
		return ""
	}
}
