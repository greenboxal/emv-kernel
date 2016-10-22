package emv

type ProcessingOptions struct {
	Aip int                 `tlv:"82"`
	Afl ApplicationFileList `tlv:"94"`
}
