package emv

type ContextConfig struct {
	Terminal     Terminal
	Applications []*ApplicationConfig
	PublicKeys   []*PublicKey
}
