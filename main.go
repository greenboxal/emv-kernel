package main

import (
	"fmt"
	"github.com/ebfe/scard"
	"github.com/greenboxal/emv-kernel/emv"
)

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

	processor := NewTransactionProcessor(card)

	err = processor.Initialize()

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	err = processor.Process()

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

}
