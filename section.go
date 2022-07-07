package pe

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strconv"
)

type SectionHeader32 struct {
	Name                 [8]uint8
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

func (sh *SectionHeader32) fullName(st StringTable) (string, error) {
	if sh.Name[0] != '/' {
		return cString(sh.Name[:]), nil
	}
	i, err := strconv.Atoi(cString(sh.Name[1:]))
	if err != nil {
		return "", err
	}
	return st.String(uint32(i))
}

type SectionHeader struct {
	Name                 string
	VirtualSize          uint32
	VirtualAddress       uint32
	Size                 uint32
	Offset               uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

type ReLoc struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

func readReLocs(sh *SectionHeader, r io.ReadSeeker) ([]ReLoc, error) {
	if sh.NumberOfRelocations <= 0 {
		return nil, nil
	}
	_, err := r.Seek(int64(sh.PointerToRelocations), io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("fail to seek to %q section relocations: %v", sh.Name, err)
	}
	reLocs := make([]ReLoc, sh.NumberOfRelocations)
	err = binary.Read(r, binary.LittleEndian, reLocs)
	if err != nil {
		return nil, fmt.Errorf("fail to read section relocations: %v", err)
	}
	return reLocs, nil
}

type Section struct {
	SectionHeader
	ReLocs []ReLoc

	io.ReaderAt
	sr *io.SectionReader
}

// Data reads and returns the contents of the PE section s.
func (s *Section) Data() ([]byte, error) {
	dat := make([]byte, s.sr.Size())
	n, err := s.sr.ReadAt(dat, 0)
	if n == len(dat) {
		err = nil
	}
	return dat[0:n], err
}

func (s *Section) GetData(start, length uint32, f *File) []byte {

	pointerToRawDataAdj := f.adjustFileAlignment(s.Offset)
	virtualAddressAdj := f.adjustSectionAlignment(s.VirtualAddress)

	var offset uint32
	if start == 0 {
		offset = pointerToRawDataAdj
	} else {
		offset = (start - virtualAddressAdj) + pointerToRawDataAdj
	}

	if offset > f.size {
		return nil
	}

	var end uint32
	if length != 0 {
		end = offset + length
	} else {
		end = offset + f.size
	}

	// PointerToRawData is not adjusted here as we might want to read any possible
	// extra bytes that might get cut off by aligning the start (and hence cutting
	// something off the end)
	if end > s.Offset+s.Size && s.Offset+s.Size > offset {
		end = s.Offset + s.Size
	}

	if end > f.size {
		end = f.size
	}

	data := make([]byte, end-offset)
	_, _ = f.sr.ReadAt(data, int64(offset))

	return data
}

// Open returns a new ReadSeeker reading the PE section s.
func (s *Section) Open() io.ReadSeeker {
	return io.NewSectionReader(s.sr, 0, 1<<63-1)
}

func (s *Section) MD5() string {
	hasher := md5.New()
	_, _ = io.Copy(hasher, s.Open())
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func (s *Section) Entropy() float64 {
	var e EntropyCalculator
	_, _ = io.Copy(&e, s.Open())
	return e.Sum()
}

func (s *Section) Flags() (flags string) {
	if (ImageScnMemRead & s.Characteristics) == ImageScnMemRead {
		flags += "r"
	}
	if (ImageScnMemExecute & s.Characteristics) == ImageScnMemExecute {
		flags += "x"
	}
	if (ImageScnMemWrite & s.Characteristics) == ImageScnMemWrite {
		flags += "w"
	}
	return flags
}

// byVirtualAddress sorts all sections by Virtual Address.
type byVirtualAddress []*Section

func (s byVirtualAddress) Len() int           { return len(s) }
func (s byVirtualAddress) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s byVirtualAddress) Less(i, j int) bool { return s[i].VirtualAddress < s[j].VirtualAddress }

func (f *File) readSections() error {
	optionalHeaderOffset := f.DOSHeader.AddressOfNewEXEHeader + 4 + uint32(binary.Size(f.NtHeader.FileHeader))
	offset := optionalHeaderOffset + uint32(f.NtHeader.FileHeader.SizeOfOptionalHeader)
	if _, err := f.sr.Seek(int64(offset), io.SeekStart); err != nil {
		return err
	}

	f.Sections = make([]*Section, f.FileHeader.NumberOfSections)
	for i := 0; i < int(f.FileHeader.NumberOfSections); i++ {
		sh := new(SectionHeader32)
		if err := binary.Read(f.sr, binary.LittleEndian, sh); err != nil {
			return err
		}
		name, err := sh.fullName(f.StringTable)
		if err != nil {
			return err
		}
		s := new(Section)
		s.SectionHeader = SectionHeader{
			Name:                 name,
			VirtualSize:          sh.VirtualSize,
			VirtualAddress:       sh.VirtualAddress,
			Size:                 sh.SizeOfRawData,
			Offset:               sh.PointerToRawData,
			PointerToRelocations: sh.PointerToRelocations,
			PointerToLineNumbers: sh.PointerToLineNumbers,
			NumberOfRelocations:  sh.NumberOfRelocations,
			NumberOfLineNumbers:  sh.NumberOfLineNumbers,
			Characteristics:      sh.Characteristics,
		}
		var r2 io.ReaderAt
		if sh.PointerToRawData == 0 { // .bss must have all 0s
			r2 = zeroReaderAt{}
		} else {
			r2 = f.f
		}
		s.sr = io.NewSectionReader(r2, int64(s.SectionHeader.Offset), int64(s.SectionHeader.Size))
		s.ReaderAt = s.sr
		f.Sections[i] = s
	}
	for i := range f.Sections {
		var err error
		f.Sections[i].ReLocs, err = readReLocs(&f.Sections[i].SectionHeader, f.sr)
		if err != nil {
			return err
		}
	}
	sort.Sort(byVirtualAddress(f.Sections))

	if f.FileHeader.NumberOfSections > 0 && len(f.Sections) > 0 {
		offset += uint32(binary.Size(SectionHeader32{})) * uint32(f.NtHeader.FileHeader.
			NumberOfSections)
	}

	var rawDataPointers []uint32
	for _, sec := range f.Sections {
		if sec.Offset > 0 {
			rawDataPointers = append(rawDataPointers, f.adjustFileAlignment(sec.Offset))
		}
	}

	var lowestSectionOffset uint32
	if len(rawDataPointers) > 0 {
		lowestSectionOffset = Min(rawDataPointers)
	} else {
		lowestSectionOffset = 0
	}

	if lowestSectionOffset == 0 || lowestSectionOffset < offset {
		if offset <= f.size {
			f.Header = make([]byte, offset)
			_, _ = f.sr.ReadAt(f.Header, 0)
		}
	} else {
		if lowestSectionOffset <= f.size {
			f.Header = make([]byte, lowestSectionOffset)
			_, _ = f.sr.ReadAt(f.Header, 0)
		}
	}
	return nil
}

// zeroReaderAt is ReaderAt that reads 0s.
type zeroReaderAt struct{}

// ReadAt writes len(p) 0s into p.
func (w zeroReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
