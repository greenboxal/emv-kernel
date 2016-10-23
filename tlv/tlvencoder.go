package tlv

type TlvEncoder interface {
	EncodeTlv() ([]byte, error)
}
