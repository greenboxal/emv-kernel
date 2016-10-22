package emv

import (
	"encoding/hex"
	"fmt"
	"github.com/ebfe/scard"
)

type Card struct {
	*scard.Card
}

func NewCard(card *scard.Card) *Card {
	return &Card{card}
}

func (e *Card) SendRawApdu(apdu *Apdu) (*ApduResponse, error) {
	dataLength := byte(0)
	fixed := 5

	if apdu.Data != nil {
		fixed = 6
		dataLength = byte(len(apdu.Data))
	}

	req := make([]byte, fixed+len(apdu.Data))

	req[0] = apdu.Class
	req[1] = apdu.Instruction
	req[2] = apdu.P1
	req[3] = apdu.P2

	if apdu.Data != nil {
		req[4] = dataLength
		copy(req[5:], apdu.Data)
		req[5+dataLength] = apdu.Expected
	} else {
		req[4] = apdu.Expected
	}

	fmt.Printf("SENT %s\n", hex.EncodeToString(req))

	res, err := e.Transmit(req)

	if err != nil {
		return nil, err
	}

	fmt.Printf("RECV %s\n", hex.EncodeToString(res))

	return &ApduResponse{
		res[:len(res)-2],
		res[len(res)-2],
		res[len(res)-1],
	}, nil
}

func (e *Card) SendApdu(apdu *Apdu) (*ApduResponse, error) {
	res, err := e.SendRawApdu(apdu)

	if err != nil {
		return nil, err
	}

	if res.SW1 == 0x61 {
		return e.SendRawApdu(&Apdu{
			Class:       0x00,
			Instruction: 0xC0,
			P1:          0x00,
			P2:          0x00,
			Expected:    res.SW2,
		})
	} else if res.SW1 == 0x6C {
		return e.SendRawApdu(&Apdu{
			Class:       apdu.Class,
			Instruction: apdu.Instruction,
			P1:          apdu.P1,
			P2:          apdu.P2,
			Data:        apdu.Data,
			Expected:    res.SW2,
		})
	}

	return res, nil
}

func (e *Card) Select(name []byte, first bool) (*ApduResponse, error) {
	var p2 byte

	if first {
		p2 = 0
	} else {
		p2 = 2
	}

	return e.SendApdu(&Apdu{
		Class:       0x00,
		Instruction: 0xA4,
		P1:          0x04,
		P2:          p2,
		Data:        []byte(name),
		Expected:    0,
	})
}

func (e *Card) ReadRecord(sfi, record byte) (*ApduResponse, error) {
	return e.SendApdu(&Apdu{
		Class:       0x00,
		Instruction: 0xB2,
		P1:          record,
		P2:          (sfi << 3) | 0x4,
		Data:        nil,
		Expected:    0,
	})
}

func (e *Card) ReadApplications(contactless bool) (bool, error) {
	var name []byte

	if contactless {
		name = []byte("2PAY.SYS.DDF01")
	} else {
		name = []byte("1PAY.SYS.DDF01")
	}

	fci, err := e.Select(name, true)

	if err != nil {
		return false, nil
	}

	if fci.SW1 == 0x90 && fci.SW2 == 0x00 {
		return true, nil
	} else {
		return false, nil
	}
}

func (e *Card) ReadApplication(name []byte) (*Application, bool, error) {
	app := &Application{}
	res, err := e.Select(name, true)

	if err != nil {
		return nil, false, err
	}

	if res.SW1 == 0x6a && res.SW2 == 0x82 {
		return nil, false, nil
	}

	if res.SW1 != 0x90 || res.SW2 != 0x00 {
		return nil, false, fmt.Errorf("Error selecting application")
	}

	body, err := DecodeTlv(res.Body)

	if err != nil {
		return nil, true, err
	}

	found, err := body.UnmarshalValue(0x6f, app)

	if err != nil {
		return nil, true, err
	}

	if !found {
		return nil, true, fmt.Errorf("Error decoding application")
	}

	return app, true, nil
}

func (e *Card) GetProcessingOptions() (*ProcessingOptions, error) {
	res, err := e.SendApdu(&Apdu{
		Class:       0x80,
		Instruction: 0xA8,
		P1:          0x00,
		P2:          0x00,
		Data:        []byte{0x83, 0x00},
		Expected:    0,
	})

	if err != nil {
		return nil, err
	}

	body, err := DecodeTlv(res.Body)

	if err != nil {
		return nil, err
	}

	po := &ProcessingOptions{}

	found, err := body.UnmarshalValue(0x77, po)

	if err != nil {
		return nil, err
	}

	if !found {
		return nil, fmt.Errorf("Invalid message")
	}

	return po, nil
}
