package emv

import "github.com/greenboxal/emv-kernel/tlv"

type DataObjectList map[int]int

func (dolPointer *DataObjectList) DecodeTlv(data []byte) error {
	if *dolPointer == nil {
		*dolPointer = make(DataObjectList)
	}

	dol := *dolPointer

	for i := 0; i < len(data); {
		tag, tagLength, err := tlv.DecodeTag(data[i:])

		if err != nil {
			return err
		}

		i += tagLength

		length, lengthLength, err := tlv.DecodeLength(data[i:])

		if err != nil {
			return err
		}

		i += lengthLength

		dol[int(tag)] = int(length)
	}

	return nil
}
