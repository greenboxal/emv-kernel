package emv

import (
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

func (c *Context) SelectApplication(applicationName []byte) error {
	app, found, err := c.card.ReadApplication(applicationName)

	if err != nil {
		return err
	}

	if !found {
		return fmt.Errorf("application not found")
	}

	opts, err := c.card.GetProcessingOptions()

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

func (c *Context) ProcessTransaction(tx *Transaction) (*TransactionResult, error) {
	tlv := make(tlv.Tlv)

	for tag, length := range c.cardInformation.RiskManagementData {
		switch tag {
		case 0x9F02:
			tlv.MarhalValue(tag, tx.Amount)
		case 0x9F03:
			tlv.MarhalValue(tag, tx.AdditionalAmount)
		case 0x9F1A:
			tlv.MarhalValue(tag, c.config.Terminal.CountryCode)
		case 0x95:
			tlv.MarhalValue(tag, c.tvr)
		case 0x5F2A:
			tlv.MarhalValue(tag, c.config.Terminal.CurrencyCode)
		case 0x9A:
			tlv.MarhalValue(tag, tx.Date)
		case 0x9C:
			tlv.MarhalValue(tag, tx.Type)
		case 0x9F37:
			number, err := c.generateUnpredictableNumber(length)

			if err != nil {
				return nil, err
			}

			tlv.MarhalValue(tag, number)
		case 0x9F35:
			tlv.MarhalValue(tag, c.config.Terminal.Type)
		case 0x9F45:
			// Do nothing for now. WTF?
		case 0x9F34:
			tlv.MarhalValue(tag, c.cvr)
		}
	}

	return nil, nil
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
