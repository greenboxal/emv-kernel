package emv

type ApplicationInformation struct {
	Name     []byte `tlv:"4F"`
	Label    string `tlv:"50"`
	Priority int    `tlv:"87"`
}
