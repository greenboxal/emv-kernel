package emv

type CardInformation struct {
	Raw Tlv `tlv:"other"`
}
