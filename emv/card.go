package emv

import (
	"encoding/hex"
	"fmt"
	"github.com/ebfe/scard"
	"github.com/greenboxal/emv-kernel/tlv"
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

func (e *Card) ReadRecord(sfi, record int) (*ApduResponse, error) {
	return e.SendApdu(&Apdu{
		Class:       0x00,
		Instruction: 0xB2,
		P1:          byte(record),
		P2:          (byte(sfi) << 3) | 0x4,
		Data:        nil,
		Expected:    0,
	})
}

func (e *Card) SelectApplication(name []byte, first bool) (*Application, bool, error) {
	app := &Application{}
	res, err := e.Select(name, first)

	if err != nil {
		return nil, false, err
	}

	if res.SW1 == 0x6a && res.SW2 == 0x82 {
		return nil, false, nil
	}

	if res.SW1 != 0x90 || res.SW2 != 0x00 {
		return nil, false, fmt.Errorf("Error selecting application")
	}

	body, err := tlv.DecodeTlv(res.Body)

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

func (e *Card) GetProcessingOptions(pdol tlv.Tlv) (*ProcessingOptions, error) {
	pdolData, err := pdol.EncodeTlv()

	if err != nil {
		return nil, err
	}

	res, err := e.SendApdu(&Apdu{
		Class:       0x80,
		Instruction: 0xA8,
		P1:          0x00,
		P2:          0x00,
		Data:        pdolData,
		Expected:    0,
	})

	if err != nil {
		return nil, err
	}

	body, err := tlv.DecodeTlv(res.Body)

	if err != nil {
		return nil, err
	}

	po := &ProcessingOptions{}

	found, err := body.UnmarshalValue(0x77, po)

	if err != nil {
		return nil, err
	}

	if !found {
		raw, found, err := body.Bytes(0x80)

		if err != nil {
			return nil, err
		}

		if !found {
			return nil, fmt.Errorf("Invalid message")
		}

		aip, err := tlv.DecodeInteger(raw[0:2])

		if err != nil {
			return nil, err
		}

		po.ApplicationInterchangeProfile = int(aip)
		po.ApplicationFileList.DecodeTlv(raw[2:])
	}

	fmt.Printf("%#+v\n", po)

	return po, nil
}

func (e *Card) VerifyPin(pin string) (bool, error) {
	pinBlock := make([]byte, 8)

	if len(pin) < 4 || len(pin) > 12 {
		return false, fmt.Errorf("wrong pin size")
	}

	pinBlock[0] = byte((1 << 5) | len(pin))

	for i := 0; i < 12; i++ {
		digit := byte(0)

		if i < len(pin) {
			digit = byte(pin[i] - '0')
		} else {
			digit = 0xF
		}

		offset := i / 2
		nibble := 1 - (i % 2)
		shift := nibble * 4

		pinBlock[1+offset] |= digit << uint(shift)
	}

	pinBlock[7] = 0xFF

	res, err := e.SendApdu(&Apdu{
		Class:       0x00,
		Instruction: 0x20,
		P1:          0x00,
		P2:          1 << 7,
		Data:        pinBlock,
		Expected:    0,
	})

	if err != nil {
		return false, err
	}

	return res.SW1 == 0x90 && res.SW2 == 0x00, nil
}

func (e *Card) GenerateAC(kind int, dol tlv.Tlv) (*GeneratedAC, error) {
	data, err := dol.EncodeTlv()

	if err != nil {
		return nil, err
	}

	res, err := e.SendApdu(&Apdu{
		Class:       0x80,
		Instruction: 0xAE,
		P1:          byte(kind),
		P2:          0x00,
		Data:        data,
		Expected:    0,
	})

	if res.SW1 != 0x90 && res.SW2 != 0x00 {
		return nil, fmt.Errorf("an error ocurred processing command")
	}

	body, err := tlv.DecodeTlv(res.Body)

	if err != nil {
		return nil, err
	}

	ac := &GeneratedAC{}

	found, err := body.UnmarshalValue(0x77, ac)

	if err != nil {
		return nil, err
	}

	if !found {
		return nil, fmt.Errorf("an error ocurred processing command")
	}

	return ac, nil
}
