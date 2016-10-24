package emv

type TransactionResult struct {
	Approved       bool
	ShouldGoOnline bool
	CryptogramType CryptogramType
	Cryptogram     []byte
}
