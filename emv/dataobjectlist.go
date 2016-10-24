package emv

import "github.com/greenboxal/emv-kernel/tlv"

type DataObjectList map[int]int

func (dol DataObjectList) DecodeTlv(data []byte) error {
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
