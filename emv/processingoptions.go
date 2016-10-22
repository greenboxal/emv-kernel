package emv

type ProcessingOptions struct {
	ApplicationInterchangeProfile int                 `tlv:"82"`
	ApplicationFileList           ApplicationFileList `tlv:"94"`
}
