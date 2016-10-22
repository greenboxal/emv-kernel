package emv

type TlvDecoder interface {
	DecodeTlv(data []byte) error
}
