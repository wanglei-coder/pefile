package pe

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

type (
	ImageResourceDirectory struct {
		Characteristics      uint32
		TimeDateStamp        uint32
		MajorVersion         uint16
		MinorVersion         uint16
		NumberOfNamedEntries uint16
		NumberOfIDEntries    uint16
	}

	ImageResourceDirectoryEntry struct {
		Name         uint32
		OffsetToData uint32
	}

	ImageResourceDataEntry struct {
		OffsetToData uint32
		Size         uint32
		CodePage     uint32
		Reserved     uint32
	}

	ResourceDirectory struct {
		Struct  ImageResourceDirectory
		Entries []ResourceDirectoryEntry
	}

	ResourceDirectoryEntry struct {
		Struct    ImageResourceDirectoryEntry
		Name      string
		ID        uint32
		Directory ResourceDirectory
		Data      ResourceDataEntry
	}

	ResourceDataEntry struct {
		Struct  ImageResourceDataEntry
		Lang    uint32
		SubLang uint32
	}
)

func (f *File) parseResourceDataEntry(rva uint32) (dataEntry ImageResourceDataEntry, err error) {
	dataEntrySize := uint32(binary.Size(dataEntry))
	offset := f.getOffsetFromRva(rva)
	if err := f.structUnpack(&dataEntry, offset, dataEntrySize); err != nil {
		return dataEntry, errors.Wrap(err, "Error parsing a resource directory data entry, the RVA is invalid")
	}
	return dataEntry, nil
}

func (f *File) parseResourceDirectoryEntry(rva uint32) *ImageResourceDirectoryEntry {
	var resource ImageResourceDirectoryEntry
	resourceSize := uint32(binary.Size(resource))
	offset := f.getOffsetFromRva(rva)
	err := f.structUnpack(&resource, offset, resourceSize)
	if err != nil {
		return nil
	}

	if resource == (ImageResourceDirectoryEntry{}) {
		return nil
	}
	return &resource
}

func (f *File) doParseResourceDirectory(rva, size, baseRVA, level uint32, dirs []uint32) (*ResourceDirectory, error) {

	var resourceDir ImageResourceDirectory
	resourceDirSize := uint32(binary.Size(resourceDir))
	offset := f.getOffsetFromRva(rva)
	err := f.structUnpack(&resourceDir, offset, resourceDirSize)
	if err != nil {
		return nil, err
	}

	if baseRVA == 0 {
		baseRVA = rva
	}

	if len(dirs) == 0 {
		dirs = append(dirs, rva)
	}

	rva += resourceDirSize

	numberOfEntries := int(resourceDir.NumberOfNamedEntries + resourceDir.NumberOfIDEntries)
	var dirEntries []ResourceDirectoryEntry

	if numberOfEntries > maxAllowedEntries {
		return nil, nil
	}

	for i := 0; i < numberOfEntries; i++ {
		res := f.parseResourceDirectoryEntry(rva)
		if res == nil {
			break
		}

		nameIsString := (res.Name & 0x80000000) >> 31
		entryName := ""
		entryID := uint32(0)
		if nameIsString == 0 {
			entryID = res.Name
		} else {
			nameOffset := res.Name & 0x7FFFFFFF
			uStringOffset := f.getOffsetFromRva(baseRVA + nameOffset)
			maxLen, err := f.ReadUint16(uStringOffset)
			if err != nil {
				break
			}
			entryName = f.readUnicodeStringAtRVA(baseRVA+nameOffset+2,
				uint32(maxLen))
		}

		dataIsDirectory := (res.OffsetToData & 0x80000000) >> 31

		OffsetToDirectory := res.OffsetToData & 0x7FFFFFFF
		if dataIsDirectory > 0 {
			if intInSlice(baseRVA+OffsetToDirectory, dirs) {
				break
			}

			level++
			dirs = append(dirs, baseRVA+OffsetToDirectory)
			directoryEntry, _ := f.doParseResourceDirectory(
				baseRVA+OffsetToDirectory,
				size-(rva-baseRVA),
				baseRVA,
				level,
				dirs)

			dirEntries = append(dirEntries, ResourceDirectoryEntry{
				Struct:    *res,
				Name:      entryName,
				ID:        entryID,
				Directory: *directoryEntry})
		} else {
			// data is entry
			dataEntryStruct, err := f.parseResourceDataEntry(baseRVA + OffsetToDirectory)
			if err != nil {
				continue
			}
			entryData := ResourceDataEntry{
				Struct:  dataEntryStruct,
				Lang:    res.Name & 0x3ff,
				SubLang: res.Name >> 10,
			}

			dirEntries = append(dirEntries, ResourceDirectoryEntry{
				Struct: *res,
				Name:   entryName,
				ID:     entryID,
				Data:   entryData})
		}

		rva += uint32(binary.Size(res))
	}

	return &ResourceDirectory{Struct: resourceDir, Entries: dirEntries}, nil
}

func (f *File) readResourceDirectory() (*ResourceDirectory, error) {
	if f.OptionalHeader == nil {
		return nil, nil
	}

	var rva, size uint32
	switch f.Is64 {
	case true:
		oh := f.OptionalHeader.(*OptionalHeader64)
		rva = oh.DataDirectory[ImageDirectoryEntryResource].VirtualAddress
		size = oh.DataDirectory[ImageDirectoryEntryResource].Size
	case false:
		oh := f.OptionalHeader.(*OptionalHeader32)
		rva = oh.DataDirectory[ImageDirectoryEntryResource].VirtualAddress
		size = oh.DataDirectory[ImageDirectoryEntryResource].Size
	}
	var dirs []uint32
	return f.doParseResourceDirectory(rva, size, 0, 0, dirs)
}
