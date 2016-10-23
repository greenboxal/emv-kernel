package tlv

import "fmt"

// Taken from: https://github.com/cdevr/WapSNMP

func EncodeTag(tag int) []byte {
	if (tag>>8)&0x1F == 0 {
		return []byte{byte(tag)}
	}

	return []byte{byte(tag >> 8), byte(tag & 0xff)}
}

func DecodeTag(toparse []byte) (int, int, error) {
	if toparse[0]&0x1F != 0x1F {
		return int(toparse[0]), 1, nil
	}

	return (int(toparse[0]) << 8) | int(toparse[1]), 2, nil
}

// EncodeLength encodes an integer value as a BER compliant length value.
func EncodeLength(length uint64) []byte {
	// The first bit is used to indicate whether this is the final byte
	// encoding the length. So, if the first bit is 0, just return a one
	// byte response containing the byte-encoded length.
	if length <= 0x7f {
		return []byte{byte(length)}
	}

	// If the length is bigger the format is, first bit 1 + the rest of the
	// bits in the first byte encode the length of the length, then follows
	// the actual length.

	// Technically the SNMP spec allows for packet lengths longer than can be
	// specified in a 127-byte encoded integer, however, going out on a limb
	// here, I don't think I'm going to support a use case that insane.

	r := EncodeUInt(length)
	numOctets := len(r)
	result := make([]byte, 1+numOctets)
	result[0] = 0x80 | byte(numOctets)
	for i, b := range r {
		result[1+i] = b
	}
	return result
}

// DecodeLength returns the length and the length of the length or an error.
//
// Caveats: Does not support indefinite length. Couldn't find any
// SNMP packet dump actually using that.
func DecodeLength(toparse []byte) (uint64, int, error) {
	// If the first bit is zero, the rest of the first byte indicates the length. Values up to 127 are encoded this way (unless you're using indefinite length, but we don't support that)

	if toparse[0] == 0x80 {
		return 0, 0, fmt.Errorf("we don't support indefinite length encoding")
	}
	if toparse[0]&0x80 == 0 {
		return uint64(toparse[0]), 1, nil
	}

	// If the first bit is one, the rest of the first byte encodes the length of then encoded length. So read how many bytes are part of the length.
	numOctets := int(toparse[0] & 0x7f)
	if len(toparse) < 1+numOctets {
		return 0, 0, fmt.Errorf("invalid length")
	}

	// Decode the specified number of bytes as a BER Integer encoded
	// value.
	val, err := DecodeUInt(toparse[1 : numOctets+1])
	if err != nil {
		return 0, 0, err
	}

	return val, 1 + numOctets, nil
}

// DecodeInteger decodes an integer.
//
// Will error out if it's longer than 64 bits.
func DecodeInteger(toparse []byte) (int64, error) {
	if len(toparse) > 8 {
		return 0, fmt.Errorf("don't support more than 64 bits")
	}
	var val int64
	for _, b := range toparse {
		val = val<<8 | int64(b)
	}
	// Extend sign if necessary.
	val <<= 64 - uint8(len(toparse))*8
	val >>= 64 - uint8(len(toparse))*8
	return val, nil
}

// DecodeUInt decodes an unsigned int.
//
// Will error out if it's longer than 64 bits.
func DecodeUInt(toparse []byte) (uint64, error) {
	if len(toparse) > 8 {
		return 0, fmt.Errorf("don't support more than 64 bits")
	}
	var val uint64
	for _, b := range toparse {
		val = val<<8 | uint64(b)
	}
	return val, nil
}

// EncodeInteger encodes an integer to BER format.
func EncodeInteger(toEncode int64) []byte {
	// Calculate the length we'll need for the encoded value.
	var l int64 = 1
	if toEncode > 0 {
		for i := toEncode; i > 255; i >>= 8 {
			l++
		}
	} else {
		for i := -toEncode; i > 255; i >>= 8 {
			l++
		}
		// Ensure room for the sign if necessary.
		if toEncode < 0 {
			l++
		}
	}

	// Now create a byte array of the correct length and copy the value into it.
	result := make([]byte, l)
	for i := int64(0); i < l; i++ {
		result[i] = byte(toEncode >> uint(8*(l-i-1)))
	}
	if result[0] > 127 && toEncode > 0 {
		result = append([]byte{0}, result...)
	}
	/*
		// Chop off superfluous 0xff's.
		s := 0
		for ; s+1 < len(result) && result[s] == 0xff && result[s+1] == 0xff; s++ {
		}
		return result[s:]*/
	return result
}

// EncodeUInt encodes an unsigned integer to BER format.
func EncodeUInt(toEncode uint64) []byte {
	// Calculate the length we'll need for the encoded value.
	var l int64 = 1
	for i := toEncode; i > 255; i >>= 8 {
		l++
	}

	// Now create a byte array of the correct length and copy the value into it.
	result := make([]byte, l)
	for i := int64(0); i < l; i++ {
		result[i] = byte(toEncode >> uint(8*(l-i-1)))
	}
	return result
}
