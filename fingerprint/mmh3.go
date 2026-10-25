package fingerprint

import (
	"encoding/base64"
	"math/bits"
)

// murmurHash3x86_32 computes MurmurHash3 (x86, 32-bit variant) of data with
// seed 0. This is the same algorithm used by Shodan's icon_hash field.
func murmurHash3x86_32(data []byte) int32 {
	const (
		c1 uint32 = 0xcc9e2d51
		c2 uint32 = 0x1b873593
	)

	length := len(data)
	h1 := uint32(0)

	nblocks := length / 4
	for i := 0; i < nblocks; i++ {
		k1 := uint32(data[i*4]) |
			uint32(data[i*4+1])<<8 |
			uint32(data[i*4+2])<<16 |
			uint32(data[i*4+3])<<24

		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2

		h1 ^= k1
		h1 = bits.RotateLeft32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}

	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
	}

	h1 ^= uint32(length)
	h1 = fmix32(h1)

	return int32(h1)
}

func fmix32(h uint32) uint32 {
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// FaviconHash computes the MMH3 hash of a favicon's raw bytes, matching
// Shodan's methodology: base64-encode the raw bytes (with newlines every 76
// chars), then MMH3 the encoded string.
func FaviconHash(raw []byte) int32 {
	encoded := faviconBase64(raw)
	return murmurHash3x86_32([]byte(encoded))
}

// faviconBase64 base64-encodes raw and inserts "\n" every 76 characters,
// matching the format used by Shodan (and fofa) for favicon hash computation.
func faviconBase64(raw []byte) string {
	enc := base64.StdEncoding.EncodeToString(raw)
	var buf []byte
	for len(enc) > 76 {
		buf = append(buf, enc[:76]...)
		buf = append(buf, '\n')
		enc = enc[76:]
	}
	buf = append(buf, enc...)
	buf = append(buf, '\n')
	return string(buf)
}
