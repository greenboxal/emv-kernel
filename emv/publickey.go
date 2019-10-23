package emv

import "math/big"

type PublicKey struct {
	exponent *big.Int
	modulus  *big.Int
}

func NewPublicKey(e, m *big.Int) *PublicKey {
	return &PublicKey{
		exponent: e,
		modulus:  m,
	}
}

func (pk *PublicKey) Decrypt(data []byte) ([]byte, error) {
	num := big.NewInt(0)
	num.SetBytes(data)

	result := big.NewInt(0)
	result.Exp(num, pk.exponent, pk.modulus)

	return result.Bytes(), nil
}

func (pk *PublicKey) Modulus() []byte {
	return pk.modulus.Bytes()
}
