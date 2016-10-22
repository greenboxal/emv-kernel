package emv

import (
	"fmt"
	"github.com/ebfe/scard"
)

type Context struct {
	card              *Card
	application       *Application
	processingOptions *ProcessingOptions
	cardInformation   *CardInformation

	sdaData []byte
}

func NewContext(card *Card) *Context {
	return &Context{
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

			body, err := DecodeTlv(record.Body)

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

			template, err := DecodeTlv(templateBytes)

			if err != nil {
				return err
			}

			err = template.Unmarshal(c.cardInformation)

			if err != nil {
				return err
			}
		}
	}

	fmt.Printf("%+v\n", c.cardInformation)
	fmt.Printf("%+v\n", c.processingOptions)

	return nil
}
