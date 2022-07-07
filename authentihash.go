package pe

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"sort"
)

func (f *File) AuthentihashSha512() []byte {
	return f.authentihash(sha512.New())
}
func (f *File) AuthentihashSha256() []byte {
	return f.authentihash(sha256.New())
}

func (f *File) AuthentihashSha1() []byte {
	return f.authentihash(sha1.New())
}

func (f *File) AuthentihashMd5() []byte {
	return f.authentihash(md5.New())
}

func (f *File) Authentihash() []byte {
	return f.authentihash(sha256.New())
}

func (f *File) authentihash(hasher hash.Hash) []byte {
	if f.OptionalHeader == nil {
		return nil
	}

	locationMap, err := f.parsePEHeaderLocations()
	if err != nil {
		return nil
	}

	locationSlice := make([]RelRange, 0, len(locationMap))
	keys := []string{"checksum", "datadir_certtable", "certtable"}
	for k, v := range locationMap {
		if stringInSlice(k, keys) {
			locationSlice = append(locationSlice, *v)
		}
	}
	sort.Sort(byStart(locationSlice))

	ranges := make([]*Range, 0, len(locationSlice))
	start := uint32(0)
	for _, r := range locationSlice {
		ranges = append(ranges, &Range{Start: start, End: r.Start})
		start = r.Start + r.Length
	}
	ranges = append(ranges, &Range{Start: start, End: f.size})

	for _, v := range ranges {
		sr := io.NewSectionReader(f.sr, int64(v.Start), int64(v.End)-int64(v.Start))
		_, _ = io.Copy(hasher, sr)
	}
	return hasher.Sum(nil)
}

type Range struct {
	Start uint32
	End   uint32
}
type RelRange struct {
	Start  uint32
	Length uint32
}

type byStart []RelRange

func (s byStart) Len() int           { return len(s) }
func (s byStart) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s byStart) Less(i, j int) bool { return s[i].Start < s[j].Start }

func (f *File) parsePEHeaderLocations() (map[string]*RelRange, error) {
	location := make(map[string]*RelRange, 3)
	optionalHeaderOffset := f.DOSHeader.AddressOfNewEXEHeader + 4 + uint32(binary.Size(f.FileHeader))

	var (
		oh32 *OptionalHeader32
		oh64 *OptionalHeader64

		optionalHeaderSize uint32
	)

	switch f.Is64 {
	case true:
		oh64 = f.OptionalHeader.(*OptionalHeader64)
		optionalHeaderSize = oh64.SizeOfHeaders
	case false:
		oh32 = f.OptionalHeader.(*OptionalHeader32)
		optionalHeaderSize = oh32.SizeOfHeaders
	}

	if optionalHeaderSize > f.size-optionalHeaderOffset {
		msgF := "the optional header exceeds the file length (%d + %d > %d)"
		return nil, fmt.Errorf(msgF, optionalHeaderSize, optionalHeaderOffset, f.size)
	}

	if optionalHeaderSize < 68 {
		msgF := "the optional header size is %d < 68, which is insufficient for authenticode"
		return nil, fmt.Errorf(msgF, optionalHeaderSize)
	}

	// The location of the checksum
	location["checksum"] = &RelRange{optionalHeaderOffset + 64, 4}

	var rvaBase, certBase, numberOfRvaAndSizes uint32
	switch f.Is64 {
	case true:
		rvaBase = optionalHeaderOffset + 108
		certBase = optionalHeaderOffset + 144
		numberOfRvaAndSizes = oh64.NumberOfRvaAndSizes
	case false:
		rvaBase = optionalHeaderOffset + 92
		certBase = optionalHeaderOffset + 128
		numberOfRvaAndSizes = oh32.NumberOfRvaAndSizes
	}

	if optionalHeaderOffset+optionalHeaderSize < rvaBase+4 {
		return location, nil
	}

	if numberOfRvaAndSizes < uint32(5) {
		return location, nil
	}

	if optionalHeaderOffset+optionalHeaderSize < certBase+8 {
		return location, nil
	}

	// The location of the entry of the Certificate Table in the Data Directory
	location["datadir_certtable"] = &RelRange{certBase, 8}

	var address, size uint32
	switch f.Is64 {
	case true:
		address = oh64.DataDirectory[ImageDirectoryEntrySecurity].VirtualAddress
		size = oh64.DataDirectory[ImageDirectoryEntrySecurity].Size
	case false:
		address = oh32.DataDirectory[ImageDirectoryEntrySecurity].VirtualAddress
		size = oh32.DataDirectory[ImageDirectoryEntrySecurity].Size
	}

	if size == 0 {
		return location, nil
	}

	if int64(address) < int64(optionalHeaderSize)+int64(optionalHeaderOffset) ||
		int64(address)+int64(size) > int64(f.size) {
		return location, nil
	}

	// The location of the Certificate Table
	location["certtable"] = &RelRange{address, size}
	return location, nil
}
