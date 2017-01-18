package emv

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"github.com/ebfe/scard"
	"github.com/greenboxal/emv-kernel/tlv"
	"math/big"
)

type Context struct {
	card   *Card
	config *ContextConfig
	cm     CertificateManager

	Application       *Application
	ProcessingOptions *ProcessingOptions
	CardInformation   *CardInformation

	tvr uint64
	cvr uint64

	sdaData                []byte
	dataAuthenticationCode []byte
}

func NewContext(card *Card, config *ContextConfig, cm CertificateManager) *Context {
	return &Context{
		config:          config,
		card:            card,
		cm:              cm,
		CardInformation: &CardInformation{},
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
					if bytes.Equal(info.Name, app.DedicatedFileName) {
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

func (c *Context) SelectApplication(applicationName []byte) (*Application, error) {
	var pdol tlv.Tlv

	app, found, err := c.card.SelectApplication(applicationName, true)

	if err != nil {
		return nil, err
	}

	if !found {
		return nil, fmt.Errorf("application not found")
	}

	if app.Template.ProcessingObjects != nil {
		pdol, err = c.buildDol(app.Template.ProcessingObjects, nil)

		if err != nil {
			return nil, err
		}
	} else {
		pdol = make(tlv.Tlv)
		pdol.MarshalValue(0x83, []byte{})
	}

	opts, err := c.card.GetProcessingOptions(pdol)

	if err != nil {
		return nil, err
	}

	c.Application = app
	c.ProcessingOptions = opts

	for _, app := range opts.ApplicationFileList {
		sdaCount := app.SdaCount

		for i := app.Start; i <= app.End; i++ {
			record, err := c.card.ReadRecord(app.Sfi, i)

			if err != nil {
				return nil, err
			}

			body, err := tlv.DecodeTlv(record.Body)

			if err != nil {
				return nil, err
			}

			templateBytes, found, err := body.Bytes(0x70)

			if err != nil {
				return nil, err
			}

			if !found {
				return nil, fmt.Errorf("malformed application file")
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
				return nil, err
			}

			err = template.Unmarshal(c.CardInformation)

			if err != nil {
				return nil, err
			}
		}
	}

	return app, nil
}

func (c *Context) Authenticate() (bool, error) {
	success := true

	if c.ProcessingOptions.ApplicationInterchangeProfile&AipDdaSupported != 0 {
		ok, err := c.authenticateDda()

		if err != nil {
			return false, err
		}

		if !ok {
			c.tvr |= TvrDdaFailed
		}

		success = success && ok
	} else if c.ProcessingOptions.ApplicationInterchangeProfile&AipSdaSupported != 0 {
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
	t := make(tlv.Tlv)

	for tag, length := range dol {
		switch tag {
		case 0x9F02:
			t.MarshalValueWithLength(tag, length, tx.Amount)
		case 0x9F03:
			t.MarshalValueWithLength(tag, length, tx.AdditionalAmount)
		case 0x9F1A:
			t.MarshalValueWithLength(tag, length, c.config.Terminal.CountryCode)
		case 0x95:
			t.MarshalValueWithLength(tag, length, c.tvr)
		case 0x5F2A:
			t.MarshalValueWithLength(tag, length, c.config.Terminal.CurrencyCode)
		case 0x9A:
			t.MarshalValueWithLength(tag, length, tx.Date)
		case 0x9C:
			t.MarshalValueWithLength(tag, length, tx.Type)
		case 0x9F37:
			number, err := c.generateUnpredictableNumber(length)

			if err != nil {
				return nil, err
			}

			t.MarshalValueWithLength(tag, length, number)
		case 0x9F35:
			t.MarshalValueWithLength(tag, length, c.config.Terminal.Type)
		case 0x9F45:
			t.MarshalValueWithLength(tag, length, c.dataAuthenticationCode)
		case 0x9F34:
			t.MarshalValueWithLength(tag, length, c.cvr)
		case 0x9F33:
			t.MarshalValueWithLength(tag, length, c.config.Terminal.Capabilities)
		case 0x9F40:
			t.MarshalValueWithLength(tag, length, c.config.Terminal.AdditionalCapabilities)
		default:
			tlvs := make([]tlv.Tlv, 0)

			if c.CardInformation != nil {
				tlvs = append(tlvs, c.CardInformation.Raw)
			}

			if c.ProcessingOptions != nil {
				tlvs = append(tlvs, c.ProcessingOptions.Raw)
			}

			t, found := tlv.Pick(tag, tlvs...)

			if found {
				value, _, _ := t.Bytes(tag)

				t.MarshalValueWithLength(tag, length, value)
			}
		}
	}

	return t, nil
}

func (c *Context) authenticateSda() (bool, error) {
	pub, err := c.retrieveIssuerPublicKey()

	if err != nil {
		return false, err
	}

	sad, err := pub.Decrypt(c.CardInformation.SignedStaticApplicationData)

	if err != nil {
		return false, err
	}

	if sad[len(sad)-1] != 0xBC {
		return false, fmt.Errorf("invalid static application data")
	}

	if sad[0] != 0x6A {
		return false, fmt.Errorf("invalid static application data")
	}

	if sad[1] != 0x03 {
		return false, fmt.Errorf("invalid static application data")
	}

	sdaTags, err := c.buildSdaTags()

	if err != nil {
		return false, err
	}

	data := sad[1:][:len(sad)-22]
	data = append(data, c.sdaData...)
	data = append(data, sdaTags...)

	actualHash := sha1.Sum(data)
	expectedHash := sad[len(sad)-21:][:20]

	if !bytes.Equal(expectedHash, actualHash[:]) {
		fmt.Printf("%x\n%x\n", actualHash, expectedHash)
		return false, fmt.Errorf("sda hash doesn't match")
	}

	c.dataAuthenticationCode = sad[3:][:2]

	return true, nil
}

func (c *Context) authenticateDda() (bool, error) {
	return false, fmt.Errorf("not implemented")
}

func (c *Context) buildSdaTags() ([]byte, error) {
	result := make([]byte, 0)

	for _, tag := range c.CardInformation.SdaTags {
		t, found := tlv.Pick(tag, c.CardInformation.Raw, c.ProcessingOptions.Raw)

		if !found {
			return nil, fmt.Errorf("missing SDA tag")
		}

		value, _, err := t.Bytes(tag)

		if err != nil {
			return nil, err
		}

		result = append(result, value...)
	}

	return result, nil
}

func (c *Context) retrieveIssuerPublicKey() (*PublicKey, error) {
	rid := c.Application.DedicatedFileName[0:5]
	index := c.CardInformation.SchemePublicKeyIndex

	pub, err := c.cm.GetSchemePublicKey(rid, index)

	if err != nil {
		return nil, err
	}

	cert, err := pub.Decrypt(c.CardInformation.IssuerPublicKeyCertificate)

	if err != nil {
		return nil, err
	}

	if cert[0] != 0x6A {
		return nil, fmt.Errorf("invalid issuer public key")
	}

	if cert[1] != 0x02 {
		return nil, fmt.Errorf("invalid issuer public key")
	}

	if cert[len(cert)-1] != 0xBC {
		return nil, fmt.Errorf("invalid issuer public key")
	}

	schemeModulus := pub.Modulus()

	keycheck := cert[1:][:14+len(schemeModulus)-36]
	keycheck = append(keycheck, c.CardInformation.IssuerPublicKeyRemainder...)
	keycheck = append(keycheck, c.CardInformation.IssuerPublicKeyExponent...)

	expectedKeycheckHash := cert[15+len(schemeModulus)-36:][:20]
	actualKeycheckHash := sha1.Sum(keycheck)

	if !bytes.Equal(expectedKeycheckHash, actualKeycheckHash[:]) {
		fmt.Printf("%x\n%x\n", expectedKeycheckHash, actualKeycheckHash)
		return nil, fmt.Errorf("hash doesn't match")
	}

	modulus := cert[15 : 15+len(schemeModulus)-36]
	modulus = append(modulus, c.CardInformation.IssuerPublicKeyRemainder...)

	e := big.NewInt(0)
	e.SetBytes(c.CardInformation.IssuerPublicKeyExponent)

	m := big.NewInt(0)
	m.SetBytes(modulus)

	return NewPublicKey(e, m), nil
}

func (c *Context) generateUnpredictableNumber(size int) ([]byte, error) {
	data := make([]byte, size)

	_, err := rand.Read(data)

	if err != nil {
		return nil, err
	}

	return data, nil
}
