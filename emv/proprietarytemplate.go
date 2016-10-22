package emv

type ProprietaryTemplate struct {
	Label              string `tlv:"50"`
	Priority           int    `tlv:"87"`
	LanguagePreference string `tlv:"5f2d"`
	DiscretionaryData  []byte `tlv:"bf0c"`
}
