package emv

type Terminal struct {
	Type         int
	CountryCode  []byte
	CurrencyCode int

	Capabilities           uint
	AdditionalCapabilities uint64
}
