package main

import (
	"encoding/hex"
	"fmt"
	"github.com/ebfe/scard"
	"github.com/greenboxal/emv-kernel/emv"
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

func getCard() (*scard.Card, error) {
	ctx, err := scard.EstablishContext()

	if err != nil {
		return nil, err
	}

	readers, err := ctx.ListReaders()

	if err != nil {
		return nil, err
	}

	fmt.Printf("Available readers:\n")
	for i, r := range readers {
		fmt.Printf("\t%d: %s\n", i, r)
	}

	selected := -1

	if len(readers) == 1 {
		selected = 0
	}

	if selected == -1 {
		return nil, err
	}

	return ctx.Connect(readers[selected], scard.ShareExclusive, scard.ProtocolAny)
}

func main() {
	rawCard, err := getCard()

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	card := emv.NewCard(rawCard)
	ctx := emv.NewContext(card)

	err = ctx.Initialize()

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	name, _ := hex.DecodeString("A0000000041010")
	err = ctx.SelectApplication(name)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	_, err = ctx.Authenticate()

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	_, err = ctx.VerifyCardholder(&terminalPinAsker{})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
}
