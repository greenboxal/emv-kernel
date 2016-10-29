package emv

type ProprietaryTemplate struct {
	Sfi                int            `tlv:"88"`
	Label              string         `tlv:"50"`
	Priority           int            `tlv:"87"`
	LanguagePreference string         `tlv:"5f2d"`
	ProcessingObjects  DataObjectList `tlv:"9F38"`
	DiscretionaryData  []byte         `tlv:"bf0c"`
}
