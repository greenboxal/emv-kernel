package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"path"
	"strconv"

	"github.com/greenboxal/emv-kernel/emv"
)

type fileCertificateManager struct {
	BasePath string
}

func (fcm *fileCertificateManager) GetSchemePublicKey(rid []byte, index int) (*emv.PublicKey, error) {
	fullPath := path.Join(fcm.BasePath, hex.EncodeToString(rid), strconv.Itoa(index)) + ".pem"

	data, err := ioutil.ReadFile(fullPath)

	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)

	if block == nil {
		return nil, errors.New("error parsing pem file")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)

	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)

	if !ok {
		return nil, errors.New("invalid public key")
	}

	return emv.NewPublicKey(big.NewInt(int64(rsaPub.E)), rsaPub.N), nil
}
