package pe

// MinFileSize On Windows XP (x32) the smallest PE executable is 97 bytes.
const MinFileSize = 97

const (
	ImageDOSSignature   = 0x5A4D // MZ
	ImageDOSZMSignature = 0x4D5A // ZM
)

const ImageNTHeaderSignature = 0x00004550

// IMAGE_DIRECTORY_ENTRY constants
const (
	ImageDirectoryEntryExport        = 0
	ImageDirectoryEntryImport        = 1
	ImageDirectoryEntryResource      = 2
	ImageDirectoryEntryException     = 3
	ImageDirectoryEntrySecurity      = 4
	ImageDirectoryEntryBaseReLoc     = 5
	ImageDirectoryEntryDebug         = 6
	ImageDirectoryEntryArchitecture  = 7
	ImageDirectoryEntryGlobalPtr     = 8
	ImageDirectoryEntryTls           = 9
	ImageDirectoryEntryLoadConfig    = 10
	ImageDirectoryEntryBoundImport   = 11
	ImageDirectoryEntryIat           = 12
	ImageDirectoryEntryDelayImport   = 13
	ImageDirectoryEntryComDescriptor = 14
)

const (
	ImageScnMemExecute = 0x20000000
	ImageScnMemRead    = 0x40000000
	ImageScnMemWrite   = 0x80000000
)

const FileAlignmentHardcodedValue = 0x200
const maxAllowedEntries = 0x1000

const (
	DansSignature = 0x536E6144
	RichSignature = "Rich"
)

const (
	imageOrdinalFlag32   = uint32(0x80000000)
	imageOrdinalFlag64   = uint64(0x8000000000000000)
	maxRepeatedAddresses = uint32(0xF)
	maxAddressSpread     = uint32(0x8000000)
	addressMask32        = uint32(0x7fffffff)
	addressMask64        = uint64(0x7fffffffffffffff)
	maxDllLength         = 0x200
	maxImportNameLength  = 0x200
)

var (
	DOSHeaderSize  = 64
	FileHeaderSize = 20
)
