package emv

import "github.com/greenboxal/emv-kernel/tlv"

type TagList []int

func (tlPointer *TagList) DecodeTlv(data []byte) error {
	if *tlPointer == nil {
		*tlPointer = make(TagList, 0)
	}

	tl := *tlPointer

	for i := 0; i < len(data); {
		tag, tagLength, err := tlv.DecodeTag(data[i:])

		if err != nil {
			return err
		}

		i += tagLength

		tl = append(tl, tag)
	}

	*tlPointer = tl

	return nil
}
