package tlv

type TlvDecoder interface {
	DecodeTlv(data []byte) error
}
