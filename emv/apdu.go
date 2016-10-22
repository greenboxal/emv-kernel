package emv

type Apdu struct {
	Class       byte
	Instruction byte
	P1          byte
	P2          byte
	Data        []byte
	Expected    byte
}
