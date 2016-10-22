package emv

import "errors"

type ApplicationFileList []ApplicationFile

func (afl *ApplicationFileList) DecodeTlv(data []byte) error {
	if len(data)%4 != 0 {
		return errors.New("len must be multiple of 4")
	}

	*afl = make(ApplicationFileList, len(data)/4)

	for i := 0; i < len(data); i += 4 {
		entry := &(*afl)[i/4]

		entry.Sfi = int(data[i] >> 3)
		entry.Start = int(data[i+1])
		entry.End = int(data[i+2])
		entry.SdaCount = int(data[i+3])
	}

	return nil
}
