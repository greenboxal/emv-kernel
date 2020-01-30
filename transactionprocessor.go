package main

import (
	"fmt"
	"github.com/greenboxal/emv-kernel/emv"
	"sort"
)

type terminalPinAsker struct{}

func (t *terminalPinAsker) RetrievePin() (string, error) {
	pin := ""

	fmt.Printf("Enter the card PIN\n")
	fmt.Printf("Please note that this COULD block your card\n")
	fmt.Printf("PIN: ")
	fmt.Scanf("%s\n", &pin)

	return pin, nil
}

type TransactionProcessor struct {
	card *emv.Card
	ctx  *emv.Context
}

func NewTransactionProcessor(card *emv.Card) *TransactionProcessor {
	return &TransactionProcessor{
		card: card,
		ctx: emv.NewContext(card, &emv.ContextConfig{
			Terminal: emv.Terminal{
				CountryCode: []byte{0x00, 0x76},
			},
		}, &fileCertificateManager{"./certs"}),
	}
}

func (t *TransactionProcessor) Initialize() error {
	err := t.ctx.Initialize()

	if err != nil {
		return err
	}

	info, err := t.selectApplication()

	if err != nil {
		return err
	}

	_, err = t.ctx.SelectApplication(info.Name)

	if err != nil {
		return err
	}

	raw, _ := t.ctx.CardInformation.Raw.EncodeTlv()
	fmt.Printf("%x\n", raw)

	_, err = t.ctx.Authenticate()

	if err != nil {
		return err
	}

	return nil
}

func (t *TransactionProcessor) selectApplication() (*emv.ApplicationInformation, error) {
	applications, err := t.ctx.ListApplications(false, hints)

	if err != nil {
		return nil, err
	}

	sort.Sort(ApplicationSorter(applications))

	if len(applications) == 0 {
		return nil, fmt.Errorf("no application available")
	}

	selected := 0

	if len(applications) == 1 && applications[0].Priority&0x80 == 0 {
		selected = 1
	} else {
		fmt.Printf("Available applications:\n")
		fmt.Printf("\t00: Cancel\n")
		for i, app := range applications {
			fmt.Printf("\t%02d: %s (%10x)\n", i+1, app.Label, app.Name)
		}
		fmt.Printf("\n")

		fmt.Printf("Enter the wanted application: ")
		fmt.Scanf("%d\n", &selected)
	}

	if selected == 0 {
		return nil, fmt.Errorf("operation was cancelled")
	}

	if selected > len(applications) {
		return nil, fmt.Errorf("invalid application selected")
	}

	app := applications[selected-1]

	fmt.Printf("Selected %s (%10x)\n", app.Label, app.Name)

	return app, nil
}

func (t *TransactionProcessor) Process() error {
	return nil
}
