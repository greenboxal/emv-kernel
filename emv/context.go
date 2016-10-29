package emv

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/ebfe/scard"
	"github.com/greenboxal/emv-kernel/tlv"
)

type Context struct {
	card   *Card
	config *ContextConfig

	application       *Application
	processingOptions *ProcessingOptions
	cardInformation   *CardInformation

	tvr uint64
	cvr uint64

	sdaData []byte
}

func NewContext(card *Card, config *ContextConfig) *Context {
	return &Context{
		config:          config,
		card:            card,
		cardInformation: &CardInformation{},
		sdaData:         []byte{},
	}
}

func (c *Context) Initialize() error {
	return c.card.Reconnect(scard.ShareExclusive, scard.ProtocolAny, scard.ResetCard)
}

func (c *Context) ListApplications(contactless bool, hints []ApplicationHint) ([]*ApplicationInformation, error) {
	var pseFile []byte

	if contactless {
		pseFile = []byte("2PAY.SYS.DDF01")
	} else {
		pseFile = []byte("1PAY.SYS.DDF01")
	}

	result := make([]*ApplicationInformation, 0)
	pse, found, err := c.card.SelectApplication(pseFile, true)

	if err != nil {
		return nil, err
	}

	if found {
		record := 1

		for true {
			res, err := c.card.ReadRecord(pse.Template.Sfi, record)

			if err != nil {
				return nil, err
			}

			if len(res.Body) == 0 {
				break
			}

			tlv, err := tlv.DecodeTlv(res.Body)

			if err != nil {
				return nil, err
			}

			tlv, found, err = tlv.Tlv(0x70)

			if err != nil {
				return nil, err
			}

			if !found {
				return nil, fmt.Errorf("invalid PSE record")
			}

			info := &ApplicationInformation{}
			found, err := tlv.UnmarshalValue(0x61, info)

			if err != nil {
				return nil, err
			}

			if !found {
				return nil, fmt.Errorf("invalid PSE record")
			}

			result = append(result, info)
			record++
		}
	} else {
		for _, hint := range hints {
			first := true

			for true {
				app, found, err := c.card.SelectApplication(hint.Name, first)

				if err != nil {
					return nil, err
				}

				if !found {
					break
				}

				duplicated := false

				for _, info := range result {
					if bytes.Compare(info.Name, app.DedicatedFileName) == 0 {
						duplicated = true
						break
					}
				}

				if !duplicated {
					result = append(result, &ApplicationInformation{
						Name:     app.DedicatedFileName,
						Label:    app.Template.Label,
						Priority: app.Template.Priority,
					})
				}

				if !hint.Partial {
					break
				}

				first = false
			}
		}
	}

	return result, nil
}

func (c *Context) SelectApplication(applicationName []byte) error {
	var pdol tlv.Tlv

	app, found, err := c.card.SelectApplication(applicationName, true)

	if err != nil {
		return err
	}

	if !found {
		return fmt.Errorf("application not found")
	}

	if app.Template.ProcessingObjects != nil {
		pdol, err = c.buildDol(app.Template.ProcessingObjects, nil)

		if err != nil {
			return err
		}
	} else {
		pdol = make(tlv.Tlv)
		pdol.MarshalValue(0x83, []byte{})
	}

	opts, err := c.card.GetProcessingOptions(pdol)

	if err != nil {
		return err
	}

	c.application = app
	c.processingOptions = opts

	for _, app := range opts.ApplicationFileList {
		sdaCount := app.SdaCount

		for i := app.Start; i <= app.End; i++ {
			record, err := c.card.ReadRecord(app.Sfi, i)

			if err != nil {
				return err
			}

			body, err := tlv.DecodeTlv(record.Body)

			if err != nil {
				return err
			}

			templateBytes, found, err := body.Bytes(0x70)

			if err != nil {
				return err
			}

			if !found {
				return fmt.Errorf("malformed application file")
			}

			// Build SDA data
			if sdaCount > 0 {
				if app.Sfi <= 10 {
					c.sdaData = append(c.sdaData, templateBytes...)
				} else {
					c.sdaData = append(c.sdaData, record.Body...)
				}

				sdaCount--
			}

			template, err := tlv.DecodeTlv(templateBytes)

			if err != nil {
				return err
			}

			err = template.Unmarshal(c.cardInformation)

			if err != nil {
				return err
			}
		}
	}

	raw, _ := c.cardInformation.Raw.EncodeTlv()

	fmt.Printf("%+v\n", c.application)
	fmt.Printf("%x\n", raw)

	return nil
}

func (c *Context) Authenticate() (bool, error) {
	success := true

	if c.processingOptions.ApplicationInterchangeProfile&AipDdaSupported != 0 {
		ok, err := c.authenticateDda()

		if err != nil {
			return false, err
		}

		if !ok {
			c.tvr |= TvrDdaFailed
		}

		success = success && ok
	} else if c.processingOptions.ApplicationInterchangeProfile&AipSdaSupported != 0 {
		ok, err := c.authenticateSda()

		if err != nil {
			return false, err
		}

		if !ok {
			c.tvr |= TvrSdaFailed
		}

		success = success && ok
	} else {
		c.tvr |= TvrOfflineNotPerformed
	}

	return true, nil
}

func (c *Context) VerifyCardholder(pinAsker PinAsker) (bool, error) {
	pin, err := pinAsker.RetrievePin()

	if err != nil {
		return false, err
	}

	ok, err := c.card.VerifyPin(pin)

	if err != nil {
		return false, err
	}

	if !ok {
		c.tvr |= TvrCvmFailed
	}

	return ok, nil
}

func (c *Context) GenerateCryptogram(tx *Transaction) (*TransactionResult, error) {
	return nil, nil
}

func (c *Context) buildDol(dol DataObjectList, tx *Transaction) (tlv.Tlv, error) {
	tlv := make(tlv.Tlv)

	for tag, length := range dol {
		switch tag {
		case 0x9F02:
			tlv.MarshalValue(tag, tx.Amount)
		case 0x9F03:
			tlv.MarshalValue(tag, tx.AdditionalAmount)
		case 0x9F1A:
			tlv.MarshalValue(tag, c.config.Terminal.CountryCode)
		case 0x95:
			tlv.MarshalValue(tag, c.tvr)
		case 0x5F2A:
			tlv.MarshalValue(tag, c.config.Terminal.CurrencyCode)
		case 0x9A:
			tlv.MarshalValue(tag, tx.Date)
		case 0x9C:
			tlv.MarshalValue(tag, tx.Type)
		case 0x9F37:
			number, err := c.generateUnpredictableNumber(length)

			if err != nil {
				return nil, err
			}

			tlv.MarshalValue(tag, number)
		case 0x9F35:
			tlv.MarshalValue(tag, c.config.Terminal.Type)
		case 0x9F45:
			// Do nothing for now. WTF?
		case 0x9F34:
			tlv.MarshalValue(tag, c.cvr)
		}
	}

	return tlv, nil
}

func (c *Context) authenticateSda() (bool, error) {
	return false, fmt.Errorf("not implemented")
}

func (c *Context) authenticateDda() (bool, error) {
	return false, fmt.Errorf("not implemented")
}

func (c *Context) generateUnpredictableNumber(size int) ([]byte, error) {
	data := make([]byte, size)

	_, err := rand.Read(data)

	if err != nil {
		return nil, err
	}

	return data, nil
}
