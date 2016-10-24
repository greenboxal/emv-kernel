package emv

type PublicKey struct {
	Rid      []byte
	Index    int
	Exponent []byte
	Modulus  []byte
}
