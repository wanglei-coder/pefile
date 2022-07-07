package pe

import (
	"encoding/binary"
	"errors"
	"io"
)

type DOSHeader struct {
	Magic                    uint16
	BytesOnLastPageOfFile    uint16
	PagesInFile              uint16
	Relocations              uint16
	SizeOfHeader             uint16
	MinExtraParagraphsNeeded uint16
	MaxExtraParagraphsNeeded uint16
	InitialSS                uint16
	InitialSP                uint16
	Checksum                 uint16
	InitialIP                uint16
	InitialCS                uint16
	AddressOfRelocationTable uint16
	OverlayNumber            uint16
	ReservedWords1           [4]uint16
	OEMIdentifier            uint16
	OEMInformation           uint16
	ReservedWords2           [10]uint16
	AddressOfNewEXEHeader    uint32
}

func (f *File) readDOSHeader() error {

	r := io.NewSectionReader(f.f, 0, int64(DOSHeaderSize))
	if err := binary.Read(r, binary.LittleEndian, &f.DOSHeader); err != nil {
		return err
	}

	if f.DOSHeader.Magic != ImageDOSSignature && f.DOSHeader.Magic != ImageDOSZMSignature {
		return errors.New("invalid PE file signature")
	}

	if f.DOSHeader.AddressOfNewEXEHeader < 4 || f.DOSHeader.AddressOfNewEXEHeader > f.size {
		return errors.New("invalid e_lfanew value. Probably not a PE file")
	}
	return nil
}
