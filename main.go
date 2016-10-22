package main

import (
	"encoding/hex"
	"fmt"
	"github.com/ebfe/scard"
	"github.com/greenboxal/emv-kernel/emv"
)

func main() {
	ctx, err := scard.EstablishContext()

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	readers, err := ctx.ListReaders()

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
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
		fmt.Printf("No readers available!\n")
		return
	}

	rawCard, err := ctx.Connect(readers[selected], scard.ShareExclusive, scard.ProtocolAny)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	card := emv.NewCard(rawCard)

	defer card.Disconnect(scard.ResetCard)

	err = card.Reconnect(scard.ShareExclusive, scard.ProtocolAny, scard.ResetCard)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	name, _ := hex.DecodeString("A0000000041010")
	app, found, err := card.ReadApplication(name)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if !found {
		fmt.Printf("Application not found\n")
		return
	}

	fmt.Printf("%+v\n", app)

	opts, err := card.GetProcessingOptions()

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("%+v\n", opts)
}
