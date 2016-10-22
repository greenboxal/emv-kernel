package emv

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTlv(t *testing.T) {
	tlv, err := hex.DecodeString("9f2701009f360200419f2608c74d18b08248fefc9f10120110201009248400000000000000000029ff")

	assert.Nil(t, err)

	decoded, err := DecodeTlv(tlv)

	assert.Nil(t, err)

	encoded := EncodeTlv(decoded)

	decoded2, err := DecodeTlv(encoded)

	assert.Nil(t, err)
	assert.Equal(t, decoded, decoded2)
}
