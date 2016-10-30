package emv

import "github.com/greenboxal/emv-kernel/tlv"

type CardInformation struct {
	Pan            string `tlv:"5A,hex"`
	SequenceNumber int    `tlv:"5F34"`
	ExpiracyDate   string `tlv:"5F24,hex"`
	HolderName     string `tlv:"5F20"`
	Track2         string `tlv:"57,hex"`

	RiskManagementData DataObjectList `tlv:"8C"`

	SchemePublicKeyIndex int `tlv:"8F"`

	IssuerPublicKeyCertificate []byte `tlv:"90"`
	IssuerPublicKeyRemainder   []byte `tlv:"92"`
	IssuerPublicKeyExponent    []byte `tlv:"9F32"`

	IccPublicKeyCertificate []byte `tlv:"9F46"`
	IccPublicKeyRemainder   []byte `tlv:"9F48"`

	SignedStaticApplicationData []byte  `tlv:"93"`
	SdaTags                     TagList `tlv:"9F4A"`

	Raw tlv.Tlv `tlv:"other"`
}
