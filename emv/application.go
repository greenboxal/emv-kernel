package emv

type Application struct {
	DedicatedFileName []byte              `tlv:"84"`
	Template          ProprietaryTemplate `tlv:"a5"`
}
