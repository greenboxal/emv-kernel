package emv

type CertificateManager interface {
	GetSchemePublicKey(rid []byte, index int) (*PublicKey, error)
}
