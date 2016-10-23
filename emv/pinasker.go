package emv

type PinAsker interface {
	RetrievePin() (string, error)
}
