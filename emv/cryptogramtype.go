package emv

type CryptogramType int

const (
	_ CryptogramType = iota

	AacCryptogram
	TcCryptogram
	ArqcCryptogram
)
