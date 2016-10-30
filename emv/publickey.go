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

func (r *PublicKey) Decrypt(data []byte) ([]byte, error) {
	num := big.NewInt(0)
	num.SetBytes(data)

	result := big.NewInt(0)
	result.Exp(num, r.exponent, r.modulus)

	return result.Bytes(), nil
}

func (r *PublicKey) Modulus() []byte {
	return r.modulus.Bytes()
}
