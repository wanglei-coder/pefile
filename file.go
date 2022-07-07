package pe

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"reflect"
)

type File struct {
	DOSHeader
	NtHeader
	Sections    []*Section
	Symbols     []*Symbol
	COFFSymbols []COFFSymbol
	StringTable StringTable

	RichHeader *RichHeader
	COFF       *COFF
	Imports    []*Import
	Resources  *ResourceDirectory
	GlobalPtr  uint32
	Header     []byte

	OverlayOffset int64

	Is64 bool
	Is32 bool
	size uint32
	f    *os.File
	sr   *io.SectionReader
}

func NewFile(filename string) (*File, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	file := new(File)
	if stat, err := f.Stat(); err != nil {
		return nil, err
	} else {
		file.size = uint32(stat.Size())
	}

	if file.size < MinFileSize {
		return nil, errors.New("not a PE file, smaller than tiny PE")
	}

	file.f = f
	file.sr = io.NewSectionReader(f, 0, int64(file.size))

	if err := file.readDOSHeader(); err != nil {
		return nil, err
	}

	if err := file.readNTHeader(); err != nil {
		return nil, err
	}

	if err := file.readRichHeader(); err != nil {
		return nil, err
	}

	if err := file.readStringTable(); err != nil {
		return nil, err
	}

	if err := file.readCOFFSymbols(); err != nil {
		return nil, err
	}

	if err := file.removeAuxSymbols(file.COFFSymbols, file.StringTable); err != nil {
		return nil, err
	}

	if err := file.readSections(); err != nil {
		return nil, err
	}
	if err := file.readImportDirectory(); err != nil {
		return nil, err
	}
	file.Resources, _ = file.readResourceDirectory()
	return file, nil
}

func (f *File) Close() error {
	if f.f != nil {
		return f.f.Close()
	}
	return nil
}

func (f *File) GetSize() uint32 {
	return f.size
}

func (f *File) Section(name string) *Section {
	for _, s := range f.Sections {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// ReadUint16 read a uint16 from a buffer.
func (f *File) ReadUint16(offset uint32) (uint16, error) {
	data := make([]byte, 2)
	if _, err := f.sr.ReadAt(data, int64(offset)); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(data), nil
}

// ReadUint32 read a uint32 from a buffer.
func (f *File) ReadUint32(offset uint32) (uint32, error) {
	data := make([]byte, 4)
	if _, err := f.sr.ReadAt(data, int64(offset)); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(data), nil
}

func (f *File) GetData(rva, length uint32) ([]byte, error) {

	section := f.getSectionByRva(rva)

	var end uint32
	if length > 0 {
		end = rva + length
	} else {
		end = 0
	}

	if section == nil {
		if rva < uint32(len(f.Header)) {
			return f.Header[rva:end], nil
		}

		if rva < f.size {
			data := make([]byte, end-rva)
			_, _ = f.sr.ReadAt(data, int64(rva))
			return data, nil
		}

		return nil, errors.New("data at RVA can't be fetched. Corrupt header?")
	}
	return section.GetData(rva, length, f), nil
}

func (f *File) GetByte(index int) (byte, error) {
	data := make([]byte, 1)
	if _, err := f.sr.ReadAt(data, int64(index)); err != nil {
		return 0, err
	}
	return data[0], nil
}

func (f *File) SectionContains(rva uint32, section *Section) bool {
	var size uint32
	adjustedPointer := f.adjustFileAlignment(section.Offset)
	if f.size-adjustedPointer < section.Size {
		size = section.VirtualSize
	} else {
		size = Max(section.Size, section.VirtualSize)
	}
	vaAdj := f.adjustSectionAlignment(section.VirtualAddress)

	// Check whether there's any section after the current one that starts before
	// the calculated end for the current one. If so, cut the current section's
	// size to fit in the range up to where the next section starts.
	if f.NextHeaderAddr(section) != 0 && f.NextHeaderAddr(section) > section.VirtualAddress &&
		vaAdj+size > f.NextHeaderAddr(section) {
		size = f.NextHeaderAddr(section) - vaAdj
	}

	return vaAdj <= rva && rva < vaAdj+size
}

// NextHeaderAddr returns the VirtualAddress of the next section.
func (f *File) NextHeaderAddr(section *Section) uint32 {
	for i, currentSection := range f.Sections {
		if i == len(f.Sections)-1 {
			return 0
		}

		if reflect.DeepEqual(section.SectionHeader, &currentSection.SectionHeader) {
			return f.Sections[i+1].VirtualAddress
		}
	}
	return 0
}

func (f *File) structUnpack(iface interface{}, offset, size uint32) (err error) {
	// Boundary check
	totalSize := offset + size

	// Integer overflow
	if (totalSize > offset) != (size > 0) {
		return ErrOutsideBoundary
	}

	if offset >= f.size || totalSize > f.size {
		return ErrOutsideBoundary
	}

	sr := io.NewSectionReader(f.sr, int64(offset), int64(offset+size))
	err = binary.Read(sr, binary.LittleEndian, iface)
	if err != nil {
		return err
	}
	return nil
}
func (f *File) adjustSectionAlignment(va uint32) uint32 {
	var fileAlignment, sectionAlignment uint32

	switch f.Is64 {
	case true:
		fileAlignment = f.OptionalHeader.(*OptionalHeader64).FileAlignment
		sectionAlignment = f.OptionalHeader.(*OptionalHeader64).SectionAlignment
	case false:
		fileAlignment = f.OptionalHeader.(*OptionalHeader32).FileAlignment
		sectionAlignment = f.OptionalHeader.(*OptionalHeader32).SectionAlignment
	}

	if sectionAlignment < 0x1000 {
		sectionAlignment = fileAlignment
	}

	if sectionAlignment != 0 && va%sectionAlignment != 0 {
		return sectionAlignment * (va / sectionAlignment)
	}
	return va
}

func (f *File) adjustFileAlignment(va uint32) uint32 {
	var fileAlignment uint32
	switch f.Is64 {
	case true:
		fileAlignment = f.OptionalHeader.(*OptionalHeader64).FileAlignment
	case false:
		fileAlignment = f.OptionalHeader.(*OptionalHeader32).FileAlignment
	}

	if fileAlignment < uint32(FileAlignmentHardcodedValue) {
		return va
	}
	return (va / 0x200) * 0x200
}

func (f *File) getOffsetFromRva(rva uint32) uint32 {
	section := f.getSectionByRva(rva)
	if section == nil {
		if rva < f.size {
			return rva
		}
		return ^uint32(0)
	}
	sectionAlignment := f.adjustSectionAlignment(section.VirtualAddress)
	fileAlignment := f.adjustFileAlignment(section.Offset)
	return rva - sectionAlignment + fileAlignment
}

func (f *File) getSectionByRva(rva uint32) *Section {
	for _, section := range f.Sections {
		if f.SectionContains(rva, section) {
			return section
		}
	}
	return nil
}

func (f *File) readUnicodeStringAtRVA(rva uint32, maxLength uint32) string {
	str := ""
	offset := f.getOffsetFromRva(rva)
	i := uint32(0)
	for i = 0; i < maxLength; i += 2 {
		if offset >= f.size-1 {
			break
		}

		data := make([]byte, 1)
		_, err := f.sr.ReadAt(data, int64(offset+i))
		if err != nil || data[0] == 0 {
			break
		}

		str += string(data[0])
	}
	return str
}

func (f *File) getStringAtRVA(rva, maxLen uint32) string {
	if rva == 0 {
		return ""
	}

	section := f.getSectionByRva(rva)
	if section == nil {
		if rva > f.size {
			return ""
		}

		end := rva + maxLen
		if end > f.size {
			end = f.size
		}
		data := make([]byte, end-rva)
		_, _ = f.sr.ReadAt(data, int64(rva))
		s := f.GetStringFromData(0, data)
		return string(s)
	}
	s := f.GetStringFromData(0, section.GetData(rva, maxLen, f))
	return string(s)
}

func (f *File) GetStringFromData(offset uint32, data []byte) []byte {

	dataSize := uint32(len(data))
	if dataSize == 0 {
		return nil
	}

	if offset > dataSize {
		return nil
	}

	end := offset
	for end < dataSize {
		if data[end] == 0 {
			break
		}
		end++
	}
	return data[offset:end]
}
