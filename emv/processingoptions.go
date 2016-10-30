package emv

import "github.com/greenboxal/emv-kernel/tlv"

type ProcessingOptions struct {
	ApplicationInterchangeProfile int                 `tlv:"82"`
	ApplicationFileList           ApplicationFileList `tlv:"94"`

	Raw tlv.Tlv `tlv:"other"`
}
