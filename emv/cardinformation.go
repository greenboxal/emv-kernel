package emv

type CardInformation struct {
	Pan            string `tlv:"5A,hex"`
	SequenceNumber int    `tlv:"5F34"`
	ExpiracyDate   string `tlv:"5F24,hex"`
	HolderName     string `tlv:"5F20"`
	Track2         string `tlv:"57,hex"`

	Raw Tlv `tlv:"other"`
}
