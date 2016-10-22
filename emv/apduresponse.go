package emv

type ApduResponse struct {
	Body []byte
	SW1  byte
	SW2  byte
}
