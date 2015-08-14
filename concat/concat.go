package concat

import (
	"crypto"
	"encoding/binary"
	"hash"
	"io"
)

type concat_key struct {
	z, info []byte
	i       uint32
	cache   []byte
	hasher  hash.Hash
}

func NewConcatKey(hash crypto.Hash, z, alg, pt_u, pt_v, sup_pub, sup_pri []byte) io.Reader {
	buf := make([]byte, len(alg)+len(pt_u)+len(pt_v)+len(sup_pri)+len(sup_pub))
	n := copy(buf, alg)
	n += copy(buf[n:], pt_u)
	n += copy(buf[n:], pt_v)
	n += copy(buf[n:], sup_pub)
	copy(buf[n:], sup_pri)

	her := hash.New()

	return &concat_key{
		z:      z,
		info:   buf,
		hasher: her,
		cache:  []byte{},
		i:      1,
	}
}

func (c *concat_key) Read(out []byte) (int, error) {
	copied := copy(out, c.cache)
	c.cache = c.cache[copied:]

	for copied < len(out) {
		c.hasher.Reset()

		binary.Write(c.hasher, binary.BigEndian, c.i)
		c.hasher.Write(c.z)
		c.hasher.Write(c.info)

		h := c.hasher.Sum(nil)
		chunk_copied := copy(out[copied:], h)
		copied += chunk_copied
		c.cache = h[chunk_copied:]
		c.i += 1
	}
	return copied, nil
}
