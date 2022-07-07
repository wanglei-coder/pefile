package pe

import (
	"encoding/binary"
	"io"

	"github.com/pkg/errors"
)

type NtHeader struct {
	Signature      uint32
	FileHeader     FileHeader
	OptionalHeader any // of type *OptionalHeader32 or *OptionalHeader64
}

type FileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type OptionalHeader32 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]DataDirectory
}

type OptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]DataDirectory
}

func (f *File) readNTHeader() (err error) {
	if _, err := f.sr.Seek(int64(f.DOSHeader.AddressOfNewEXEHeader), io.SeekStart); err != nil {
		return err
	}

	if err := binary.Read(f.sr, binary.LittleEndian, &f.Signature); err != nil {
		return err
	}

	if f.Signature != ImageNTHeaderSignature {
		return errors.New("not a valid PE signature. Magic not found")
	}

	if err := binary.Read(f.sr, binary.LittleEndian, &f.FileHeader); err != nil {
		return err
	}

	f.OptionalHeader, err = f.readOptionalHeader(f.sr)
	return err
}

func (f *File) readOptionalHeader(r io.ReadSeeker) (any, error) {
	if f.FileHeader.SizeOfOptionalHeader == 0 {
		return nil, nil
	}

	var (
		ohMagic   uint16
		ohMagicSz = binary.Size(ohMagic)
	)

	// If optional header size is greater than 0 but less than its magic size, return error.
	if f.FileHeader.SizeOfOptionalHeader < uint16(ohMagicSz) {
		return nil, errors.New("optional header size is less than optional header magic size")
	}

	var err error
	read := func(data any) bool {
		err = binary.Read(r, binary.LittleEndian, data)
		return err == nil
	}

	if !read(&ohMagic) {
		return nil, errors.WithMessage(err, "failure to read optional header magic")
	}

	switch ohMagic {
	case 0x10b: // PE32
		var (
			oh32 OptionalHeader32
			// There can be 0 or more data directories. So the minimum size of optional
			// header is calculated by subtracting oh32.DataDirectory size from oh32 size.
			oh32MinSz = binary.Size(oh32) - binary.Size(oh32.DataDirectory)
		)

		if f.FileHeader.SizeOfOptionalHeader < uint16(oh32MinSz) {
			return nil, errors.Errorf("optional header size(%d) is less minimum size ("+
				"%d) of PE32 optional header", f.FileHeader.SizeOfOptionalHeader, oh32MinSz)
		}

		// Init oh32 fields
		oh32.Magic = ohMagic
		if !read(&oh32.MajorLinkerVersion) ||
			!read(&oh32.MinorLinkerVersion) ||
			!read(&oh32.SizeOfCode) ||
			!read(&oh32.SizeOfInitializedData) ||
			!read(&oh32.SizeOfUninitializedData) ||
			!read(&oh32.AddressOfEntryPoint) ||
			!read(&oh32.BaseOfCode) ||
			!read(&oh32.BaseOfData) ||
			!read(&oh32.ImageBase) ||
			!read(&oh32.SectionAlignment) ||
			!read(&oh32.FileAlignment) ||
			!read(&oh32.MajorOperatingSystemVersion) ||
			!read(&oh32.MinorOperatingSystemVersion) ||
			!read(&oh32.MajorImageVersion) ||
			!read(&oh32.MinorImageVersion) ||
			!read(&oh32.MajorSubsystemVersion) ||
			!read(&oh32.MinorSubsystemVersion) ||
			!read(&oh32.Win32VersionValue) ||
			!read(&oh32.SizeOfImage) ||
			!read(&oh32.SizeOfHeaders) ||
			!read(&oh32.CheckSum) ||
			!read(&oh32.Subsystem) ||
			!read(&oh32.DllCharacteristics) ||
			!read(&oh32.SizeOfStackReserve) ||
			!read(&oh32.SizeOfStackCommit) ||
			!read(&oh32.SizeOfHeapReserve) ||
			!read(&oh32.SizeOfHeapCommit) ||
			!read(&oh32.LoaderFlags) ||
			!read(&oh32.NumberOfRvaAndSizes) {
			return nil, errors.Wrap(err, "failure to read PE32 optional header")
		}

		if oh32.ImageBase%0x10000 != 0 {
			return nil, errors.New("corrupt PE file. Image base not aligned to 64 K")
		}

		dd, err := readDataDirectories(r, f.FileHeader.SizeOfOptionalHeader-uint16(oh32MinSz), oh32.NumberOfRvaAndSizes)
		if err != nil {
			return nil, err
		}

		copy(oh32.DataDirectory[:], dd)
		f.Is32 = true
		return &oh32, nil
	case 0x20b: // PE32+
		var (
			oh64 OptionalHeader64
			// There can be 0 or more data directories. So the minimum size of optional
			// header is calculated by subtracting oh64.DataDirectory size from oh64 size.
			oh64MinSz = binary.Size(oh64) - binary.Size(oh64.DataDirectory)
		)

		if f.FileHeader.SizeOfOptionalHeader < uint16(oh64MinSz) {
			return nil, errors.Errorf("optional header size(%d) is less minimum size ("+
				"%d) for PE32+ optional header", f.FileHeader.SizeOfOptionalHeader, oh64MinSz)
		}

		// Init oh64 fields
		oh64.Magic = ohMagic
		if !read(&oh64.MajorLinkerVersion) ||
			!read(&oh64.MinorLinkerVersion) ||
			!read(&oh64.SizeOfCode) ||
			!read(&oh64.SizeOfInitializedData) ||
			!read(&oh64.SizeOfUninitializedData) ||
			!read(&oh64.AddressOfEntryPoint) ||
			!read(&oh64.BaseOfCode) ||
			!read(&oh64.ImageBase) ||
			!read(&oh64.SectionAlignment) ||
			!read(&oh64.FileAlignment) ||
			!read(&oh64.MajorOperatingSystemVersion) ||
			!read(&oh64.MinorOperatingSystemVersion) ||
			!read(&oh64.MajorImageVersion) ||
			!read(&oh64.MinorImageVersion) ||
			!read(&oh64.MajorSubsystemVersion) ||
			!read(&oh64.MinorSubsystemVersion) ||
			!read(&oh64.Win32VersionValue) ||
			!read(&oh64.SizeOfImage) ||
			!read(&oh64.SizeOfHeaders) ||
			!read(&oh64.CheckSum) ||
			!read(&oh64.Subsystem) ||
			!read(&oh64.DllCharacteristics) ||
			!read(&oh64.SizeOfStackReserve) ||
			!read(&oh64.SizeOfStackCommit) ||
			!read(&oh64.SizeOfHeapReserve) ||
			!read(&oh64.SizeOfHeapCommit) ||
			!read(&oh64.LoaderFlags) ||
			!read(&oh64.NumberOfRvaAndSizes) {
			return nil, errors.Wrap(err, "failure to read PE32+ optional header")
		}

		if oh64.ImageBase%0x10000 != 0 {
			return nil, errors.New("corrupt PE file. Image base not aligned to 64 K")
		}

		dd, err := readDataDirectories(r, f.FileHeader.SizeOfOptionalHeader-uint16(oh64MinSz), oh64.NumberOfRvaAndSizes)
		if err != nil {
			return nil, err
		}

		copy(oh64.DataDirectory[:], dd)
		f.Is64 = true
		return &oh64, nil
	default:
		return nil, errors.Errorf("optional header has unexpected Magic of 0x%x", ohMagic)
	}
}

func readDataDirectories(r io.ReadSeeker, sz uint16, n uint32) ([]DataDirectory, error) {
	ddSz := binary.Size(DataDirectory{})
	if uint32(sz) != n*uint32(ddSz) {
		return nil, errors.Errorf("size of data directories("+
			"%d) is inconsistent with number of data directories(%d)", sz, n)
	}

	dd := make([]DataDirectory, n)
	if err := binary.Read(r, binary.LittleEndian, dd); err != nil {
		return nil, errors.WithMessage(err, "failure to read data directories")
	}

	return dd, nil
}
