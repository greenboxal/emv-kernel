package emv

const (
	_ uint64 = 0

	AipSdaSupported           = 1 << 14
	AipDdaSupported           = 1 << 13
	AipCvmSupported           = 1 << 12
	AipTerminalRiskManagement = 1 << 11
	AipIssuerAuthentication   = 1 << 10
	AipCdaSupported           = 1 << 8

	TvrCdaFailed            = 1 << 2
	TvrDdaFailed            = 1 << 3
	TvrHotlist              = 1 << 4
	TvrIccDataMissing       = 1 << 5
	TvrSdaFailed            = 1 << 6
	TvrOfflineNotPerformed  = 1 << 7
	TvrNewCard              = 1 << 11
	TvrNotProductAllowed    = 1 << 12
	TvrNotYetEffective      = 1 << 13
	TvrExpiredApplication   = 1 << 14
	TvrDifferentVersions    = 1 << 15
	TvrOnlinePinEntered     = 1 << 18
	TvrPinNotEntered        = 1 << 19
	TvrNoPinpad             = 1 << 20
	TvrPinTryLimit          = 1 << 21
	TvrUnrecognizedCvm      = 1 << 22
	TvrCvmFailed            = 1 << 23
	TvrForcedOnline         = 1 << 27
	TvrRandomOnline         = 1 << 28
	TvrOfflineUpperLimit    = 1 << 29
	TvrOfflineLowerLimit    = 1 << 30
	TvrFloorLimit           = 1 << 31
	TvrScriptFailedAfterAC  = 1 << 36
	TvrScriptFailedBeforeAC = 1 << 37
	TvrIssuerAuthFailed     = 1 << 38
	TvrDefaulDdol           = 1 << 39

	AcAac          = 0
	AcTc           = 1 << 6
	AcArqc         = 1 << 7
	AcCdaRequested = 1 << 4
)
