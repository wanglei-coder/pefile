package pe

type ImageDelayImportDirectory struct {
	Attributes                 uint32
	Name                       uint32
	ModuleHandleRVA            uint32
	ImportAddressTableRVA      uint32
	ImportNameTableRVA         uint32
	BoundImportAddressTableRVA uint32
	UnloadInformationTableRVA  uint32
	TimeDateStamp              uint32
}

type DelayImport struct {
	Offset     uint32
	Name       string
	Functions  []*ImportFunction
	Descriptor ImageDelayImportDirectory
}
